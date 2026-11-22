#!/usr/bin/env python3
"""Inspect or declare the original daemon mode of an offline SQLite swap store."""
import argparse
from pathlib import Path
import json
import sqlite3
import sys

MODES = {"live": 0x53574C56, "mock": 0x53574D4B}
COLUMNS = {
    "quotes": "id json",
    "maker_swaps": "id created_at state json",
    "taker_swaps": "id seq json",
    "docs": "kind id seq json",
    "input_reservation": "chain in_txid in_vout reserved_by",
    "lock_absence": "chain lock_txid first_absent_height first_absent_hash first_absent_after",
    "expiry_tip": "chain height",
}


PRIMARY_KEYS = {
    "quotes": ["id"], "maker_swaps": ["id"], "taker_swaps": ["id"],
    "docs": ["kind", "id"], "input_reservation": ["chain", "in_txid", "in_vout"],
    "lock_absence": ["chain", "lock_txid"], "expiry_tip": ["chain"],
}
INTEGER_COLUMNS = set("created_at seq in_vout first_absent_height first_absent_after height".split())


def review(db, declared):
    version = db.execute("PRAGMA user_version").fetchone()[0]
    marker = db.execute("PRAGMA application_id").fetchone()[0]
    binding = next((m for m, v in MODES.items() if v == marker), None)
    if declared and (marker or version == 5):
        raise ValueError("existing marker or bound schema cannot be changed")
    if version not in range(6) or (version == 5) != bool(binding) or (marker and not binding):
        raise ValueError(f"unsupported schema {version} or application id {marker}")
    if db.execute("PRAGMA integrity_check").fetchall() != [("ok",)]:
        raise ValueError("SQLite integrity check failed")
    tables = dict(db.execute("SELECT name,type FROM sqlite_master WHERE type != 'index'"))
    if tables.keys() - COLUMNS.keys() or any(t != "table" for t in tables.values()):
        raise ValueError("unrecognized database objects")
    indexes = {
        "maker_swaps_hash_unique": "CREATE UNIQUE INDEX maker_swaps_hash_unique ON maker_swaps (json_extract(json, '$.hash'))",
        "input_reservation_by_tx": "CREATE INDEX input_reservation_by_tx ON input_reservation (chain, reserved_by)",
    }
    for name, sql in db.execute("SELECT name,sql FROM sqlite_master WHERE type='index' AND sql IS NOT NULL"):
        if " ".join(sql.split()) != indexes.get(name):
            raise ValueError(f"unsupported index {name}")
    counts = {}
    for table, columns in COLUMNS.items():
        if table not in tables and table in ("input_reservation", "lock_absence", "expiry_tip"):
            continue
        info = list(db.execute(f"PRAGMA table_xinfo({table})"))
        actual = [r[1] for r in info]
        if table == "lock_absence" and actual == columns.split()[:len(actual)] and len(actual) >= 3:
            columns = " ".join(actual)
        if actual != columns.split():
            raise ValueError(f"unsupported {table} schema")
        for _, name, datatype, required, default, pk, hidden in info:
            keys = PRIMARY_KEYS[table]
            nullable = name in ("first_absent_hash", "first_absent_after") or (
                name == "id" and keys == ["id"])
            if (datatype.upper() != ("INTEGER" if name in INTEGER_COLUMNS else "TEXT")
                    or bool(required) == nullable or default is not None or hidden
                    or pk != (keys.index(name) + 1 if name in keys else 0)):
                raise ValueError(f"unsupported definition of {table}.{name}")
        counts[table] = db.execute(f"SELECT count(*) FROM {table}").fetchone()[0]
    identities = set()
    for table in ("maker_swaps", "taker_swaps"):
        for (raw,) in db.execute(
                f"SELECT DISTINCT json_quote(json_extract(json, '$.usdc_admission')) FROM {table}"):
            identity = json.loads(raw)
            if identity is None:
                continue
            if identity == "Mock":
                identities.add("mock")
            elif isinstance(identity, dict) and list(identity) in (["Evm"], ["EvmContracts"]):
                identities.add("live")
            else:
                raise ValueError("unrecognized USDC admission")
    if declared and identities - {declared}:
        raise ValueError("persisted USDC admission contradicts declaration")
    return dict(schema=version, binding=binding, counts=counts, usdc_modes=sorted(identities))


def main():
    parser = argparse.ArgumentParser(description=__doc__, allow_abbrev=False)
    actions = parser.add_subparsers(dest="action", required=True)
    inspect = actions.add_parser("inspect", allow_abbrev=False)
    bind = actions.add_parser("bind", allow_abbrev=False)
    for action in (inspect, bind):
        action.add_argument("database", type=Path)
    bind.add_argument("--mode", choices=MODES, required=True)
    bind.add_argument("--attest-original-mode", choices=MODES, required=True,
                      help="declare the verified original mode; legacy records cannot prove it")
    args = parser.parse_args()
    mode = getattr(args, "mode", None)
    if mode and mode != args.attest_original_mode:
        parser.error("attestation must match the declared mode")
    uri = args.database.resolve().as_uri() + ("?mode=rw" if mode else "?mode=ro")
    db = sqlite3.connect(uri, uri=True)
    try:
        with db:
            # Keep normal connection locking: EXCLUSIVE locking_mode can retain
            # competing shared locks while both binders wait for an upgrade.
            # The transaction itself serializes review and both header writes.
            db.execute("BEGIN EXCLUSIVE" if mode else "BEGIN")
            report = review(db, mode)
            if mode:
                db.execute(f"PRAGMA application_id={MODES[mode]}")
                db.execute("PRAGMA user_version=5")
                report.update(schema=5, binding=mode)
        print(json.dumps(report, sort_keys=True))
    finally:
        db.close()


if __name__ == "__main__":
    try:
        main()
    except (ValueError, sqlite3.Error, AttributeError) as error:
        sys.exit(str(error))
