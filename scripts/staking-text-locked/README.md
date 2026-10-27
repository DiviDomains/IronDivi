# Staking replies in four wallet states, next to Divi Core

`run.sh` starts a fresh Divi Core 3.0.0 `divid` and a fresh irondivid on regtest, both with `staking=1`, each on its
own chain and with no peers. Both mine 120 blocks (`setgenerate 120`), then go through the same four states:

1. not encrypted;
2. encrypted (`encryptwallet`) and locked after a restart;
3. unlocked for staking only (`walletpassphrase <passphrase> 0 true`);
4. fully unlocked (`walletlock`, then `walletpassphrase <passphrase> 600`).

In each state it compares the staking replies field by field. Each row prints one line:

- `PASS`: same as divid;
- `KNOWN`: differs, and the difference is listed below with the reason;
- `FAIL`: differs and should not, or a `KNOWN` row that now matches divid (the list below is out of date).

The run ends with `FAILS <n>`; the exit code is the number of FAILs (255: usage error, interrupted, a node that did
not start or answer, or over 10 minutes).

```sh
scripts/staking-text-locked/run.sh <irondivid-bin-dir> <core-bin-dir> <port-base> [root]

# for example, with a release build of this tree
cargo build --release -p irondivid
scripts/staking-text-locked/run.sh target/release ~/divi-3.0.0/bin 53950 /var/tmp
```

- `<irondivid-bin-dir>` holds `irondivid`; `<core-bin-dir>` holds Divi Core's `divid`.
- `<port-base>`: ports `<port-base>` to `<port-base>+3` on 127.0.0.2 (divid p2p and RPC, then irondivid's).
- `[root]`: a fresh directory is made under it (default `$TMPDIR`, else `/tmp`) and deleted at the end.

A run takes about 30 seconds and is stopped after 10 minutes. However it ends, both nodes are stopped and their
directories deleted. Needs bash and python3 (standard library only). The wallet passphrase is made in memory; it is
never printed, written to a file or put on a command line.

## Rows, per state

- `getstakingstatus`: every field divid gives, compared (validtime, haveconnections, walletunlocked, mintablecoins,
  staking_balance, enoughcoins, mnsync, "staking status", "stake split threshold"; rpcmisc.cpp:1037-1080).
- `getstakingstatus: fields divid lacks`: the fields only irondivid gives.
- `staking status text`: irondivid's `"staking status text"` next to divid's words for its staking state, getinfo's
  `"staking status"`: "Staking Active" when the node tried to stake in the last minutes (the bool
  `"staking status"`), else "Staking Not Active" (rpcmisc.cpp:154-155). A locked wallet tries no stake.
- `getinfo staking status`: getinfo's `"staking status"` on both.
- `getmininginfo staking fields`: the getmininginfo fields with "stak" in their name (none on either).
- `encryption_status`: getwalletinfo's, to show each state was reached on both.

Right after `setgenerate 120` both nodes have hashed stake kernels for blocks 101 to 120, so state 1 is
"Staking Active" with `"staking status": true` on both; a restart clears that, and without peers neither node tries
another stake, so states 2 to 4 are "Staking Not Active" on both.

## Known differences

- `getstakingstatus: fields divid lacks`: irondivid adds `"staking status text"`, the staking state in words
  (divid's getstakingstatus has the bool only). irondivid also says "Staking Disabled" there when its staker is
  switched off (`setstaking false`, `staking=0`), a state divid's staker does not have; with `staking=1` as here it
  does not occur.

`STAKING_TEXT_INJECT=<row name>` changes irondivid's value of that row before it is compared, to show that a
difference is caught (the row then FAILs).
