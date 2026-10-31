#!/bin/sh
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 human
# IronDivi - https://github.com/DiviDomains/IronDivi
#
# contrib/diag.sh: collect IronDivi diagnostics where `irondivi-cli diag`
# cannot run (docs/plans/diag.md B1.4). POSIX sh; tested under dash, busybox
# ash and the macOS sh.
#
# It writes the "sh" subset of the diag folder layout: runs.log and the
# other Part A files, the end of debug.log, the filtered kernel log, the
# programs' headers and exec errors, and basic host facts. Nothing in the
# folder is redacted yet, so the folder is created with mode 0700 and this
# script never packs, encrypts or sends it. Run
#   irondivi-cli diag --import <folder>
# on any machine where irondivi-cli runs: the import redacts and scans the
# folder and asks before anything leaves.
#
# Usage: diag.sh [--out DIR] [--datadir DIR]... [--emit-shar]
#   --out DIR      folder to write (default ./irondivi-diag-<time>); must not
#                  exist or must be empty
#   --datadir DIR  a data dir to look at (repeatable; default: the usual ones)
#   --emit-shar    write the folder to stdout as a shell archive of printf
#                  lines instead of leaving it on disk (for an image with no
#                  tar); the host side runs it with sh inside a 0700 folder
#                  and then runs `irondivi-cli diag --import` on that folder

umask 077
LC_ALL=C
export LC_ALL

OUT=
DATADIRS=
SHAR=0
while [ $# -gt 0 ]; do
	case $1 in
	--out) OUT=$2; shift 2 ;;
	--out=*) OUT=${1#--out=}; shift ;;
	--datadir) DATADIRS="$DATADIRS
$2"; shift 2 ;;
	--datadir=*) DATADIRS="$DATADIRS
${1#--datadir=}"; shift ;;
	--emit-shar) SHAR=1; shift ;;
	-h|--help) sed -n '2,/^$/s/^# \{0,1\}//p' "$0" 2>/dev/null || echo "usage: diag.sh [--out DIR] [--datadir DIR]... [--emit-shar]"; exit 0 ;;
	*) echo "diag.sh: unknown option $1" >&2; exit 64 ;;
	esac
done

TMPOUT=0
if [ -z "$OUT" ]; then
	if [ "$SHAR" = 1 ]; then
		for t in /dev/shm "${TMPDIR:-/tmp}"; do
			OUT=$(mktemp -d "$t/irondivi-diag.XXXXXX" 2>/dev/null) && break
		done
		[ -n "$OUT" ] || { echo "diag.sh: cannot make a temporary folder; pass --out" >&2; exit 73; }
		TMPOUT=1
	else
		OUT=./irondivi-diag-$(date -u +%Y%m%dT%H%M%SZ)
	fi
fi
if [ -e "$OUT" ] && [ -n "$(ls -A "$OUT" 2>/dev/null)" ]; then
	echo "diag.sh: $OUT exists and is not empty" >&2
	exit 73
fi
mkdir -p "$OUT" && chmod 700 "$OUT" || { echo "diag.sh: cannot create $OUT" >&2; exit 73; }

# say() writes to the user, never into stdout when stdout is the archive
say() { echo "$*" >&2; }
LOG=$OUT/diag.log
note() { echo "$*" >> "$LOG"; }
put() { mkdir -p "$OUT/$(dirname "$1")" && cat >> "$OUT/$1"; }

note "collected by contrib/diag.sh (docs/plans/diag.md B1.4) at $(date -u +%Y-%m-%dT%H:%M:%SZ)"
note "NOT REDACTED: run irondivi-cli diag --import on this folder before sending anything"

# ------------------------------------------------------------ host facts
{
	echo "== uname (no nodename)"; uname -srvm 2>&1
	if [ -r /etc/os-release ]; then echo "== os-release"; cat /etc/os-release; else echo "== sw_vers"; sw_vers 2>&1; fi
	echo "== uptime"; uptime 2>&1
	echo "== id (numeric)"; echo "uid=$(id -u) gid=$(id -g) groups=$(id -G)"
	echo "== ulimit -a"; ulimit -a 2>&1
	echo "== memory"; head -n 20 /proc/meminfo 2>/dev/null || vm_stat 2>&1
	echo "== disk"; df -k 2>&1
	echo "== processes named irondivi"
	ps -eo pid,user,etime,rss,comm 2>/dev/null | grep -i '[i]rondivi'
} | put host/host.txt

# ------------------------------------------------------------ programs (B1.2)
progs=
for d in $(echo "$PATH" | tr ':' ' ') /usr/local/bin /usr/bin /opt/irondivi/bin /opt/irondivi "$HOME/bin" "$HOME/.local/bin" "$HOME/.cargo/bin" .; do
	for p in irondivid irondivi-cli; do
		[ -f "$d/$p" ] || continue
		case " $progs " in *" $d/$p "*) continue ;; esac
		progs="$progs $d/$p"
	done
done
{
	[ -n "$progs" ] || echo "no irondivid or irondivi-cli found"
	for p in $progs; do
		echo "== $p"
		ls -lL "$p" 2>&1
		command -v sha256sum >/dev/null 2>&1 && sha256sum "$p" 2>&1 | sed 's/^\([0-9a-f]*\).*/sha256:\1/'
		command -v file >/dev/null 2>&1 && file -L "$p" 2>&1
		echo "header bytes: $(head -c 20 "$p" 2>/dev/null | od -An -tx1 | tr -s ' \n' '  ')"
		if [ -x "$p" ]; then
			v=$("$p" --version 2>&1 </dev/null)
			echo "--version (exit $?): $(echo "$v" | head -n 5)"
		else
			echo "not executable"
		fi
		if command -v ldd >/dev/null 2>&1; then ldd "$p" 2>&1 | head -n 20
		elif command -v otool >/dev/null 2>&1; then otool -L "$p" 2>&1 | head -n 20; fi
	done
	echo "== libc"
	command -v ldd >/dev/null 2>&1 && ldd --version 2>&1 | head -n 1
	ls /lib/ld-musl-* 2>/dev/null
} | put binaries.txt

# ------------------------------------------------------------ data dirs
if [ -z "$DATADIRS" ]; then
	for h in "$HOME" /root /home/* /Users/*; do
		[ -d "$h/.irondivi" ] && DATADIRS="$DATADIRS
$h/.irondivi"
		[ -d "$h/Library/Application Support/IronDivi" ] && DATADIRS="$DATADIRS
$h/Library/Application Support/IronDivi"
	done
	[ -d /var/lib/irondivi ] && DATADIRS="$DATADIRS
/var/lib/irondivi"
fi

PART_A="runs.log crash.log events.log chain-events.log health.log rpc-methods.log rpc-methods-reserved.log irondivid.running"
n=0
seen=
# copy_tail <src> <rel> <bytes>
copy_tail() {
	sz=$(wc -c < "$1" 2>/dev/null | tr -d ' ')
	if [ -z "$sz" ]; then
		echo "$2: unreadable ($(cat "$1" 2>&1 >/dev/null | head -n 1))" | put logs-errors.txt
		return
	fi
	if [ "$sz" -gt "$3" ]; then
		echo "[first part cut: kept the last $3 bytes of $sz]" | put "$2"
	fi
	tail -c "$3" "$1" 2>/dev/null | put "$2"
}
# diag_dir <dir> <base>
diag_dir() {
	[ -d "$1" ] || return
	for f in $PART_A; do
		if [ -f "$1/$f" ]; then
			copy_tail "$1/$f" "$2/diag/$f" 8388608
		else
			echo "diag/$f: absent" | put "$2/README.txt"
		fi
	done
	for f in "$1"/*.log.* "$1"/rpc-aggregate*.log; do
		[ -f "$f" ] || continue
		case ${f##*/} in sent-txids*) continue ;; esac
		copy_tail "$f" "$2/diag/${f##*/}" 4194304
	done
	for sub in startup incidents; do
		[ -d "$1/$sub" ] || continue
		for f in "$1/$sub"/*; do
			[ -f "$f" ] && copy_tail "$f" "$2/diag/$sub/${f##*/}" 1048576
		done
	done
	for sub in invalid rejected-tx bad-messages; do
		if [ -d "$1/$sub" ]; then
			echo "diag/$sub/: $(ls "$1/$sub" | wc -l | tr -d ' ') files (listed only)"
		else
			echo "diag/$sub/: absent"
		fi | put "$2/README.txt"
	done
}

OLDIFS=$IFS
IFS='
'
for d in $DATADIRS; do
	[ -n "$d" ] && [ -d "$d" ] || continue
	case "
$seen
" in *"
$d
"*) continue ;; esac
	seen="$seen
$d"
	n=$((n + 1))
	base=datadir-$n/logs
	note "datadir-$n: $d"
	IFS=$OLDIFS
	{
		echo "path: $d"
		ls -ld "$d" 2>&1
		echo "== top level (names only; wallet contents are never read)"
		ls -la "$d" 2>&1
	} | put "datadir-$n/inventory.txt"
	for chain in "$d" "$d/testnet" "$d/regtest" "$d/testnet3"; do
		[ -d "$chain" ] || continue
		tag=${chain#"$d"}
		tag=${tag#/}
		b=$base${tag:+/$tag}
		if [ -f "$chain/debug.log" ]; then
			copy_tail "$chain/debug.log" "$b/debug.log" 2097152
		else
			echo "no debug.log in ${tag:-the data dir}" | put "$b/README.txt"
		fi
		diag_dir "$chain/diag" "$b"
	done
	IFS='
'
done
IFS=$OLDIFS
[ "$n" -gt 0 ] || note "no data dir found; pass --datadir"

# ------------------------------------------------------------ mirrors (A14)
k=0
for m in "${XDG_STATE_HOME:-$HOME/.local/state}/irondivi" "$HOME/Library/Logs/IronDivi" /var/log/irondivi /var/tmp/irondivi-*; do
	[ -d "$m" ] || continue
	k=$((k + 1))
	note "mirrors/root-$k: $m"
	for f in "$m"/*; do
		[ -f "$f" ] || continue
		case ${f##*/} in sent-txids*) continue ;; esac
		copy_tail "$f" "mirrors/root-$k/${f##*/}" 4194304
	done
done

# ------------------------------------------------------------ kernel log (B2.11)
PAT='irondivid|tokio-runtime-w|rocksdb:|out of memory|oom-kill|oom_reaper|invoked oom-killer|killed process|segfault|general protection|traps:|hung_task|blocked for more than|i/o error|ext4-fs|xfs|btrfs|zfs|mmc|nvme|blk_update_request|buffer i/o|thermal|under-voltage|undervoltage|clocksource|pm: suspend|pm: resume|seccomp|avc:|apparmor="denied"|memory cgroup'
{
	if out=$(dmesg 2>&1); then
		echo "== dmesg (filtered)"
		echo "$out" | grep -iE "$PAT" | tail -n 2000
	else
		echo "== dmesg: $out" | head -n 1
		if command -v journalctl >/dev/null 2>&1; then
			echo "== journalctl -k (filtered)"
			journalctl -k -b --no-pager -q 2>&1 | grep -iE "$PAT" | tail -n 2000
		elif [ "$(uname -s)" = Darwin ] && command -v log >/dev/null 2>&1; then
			echo "== log show (1 day, irondivid and kernel memory/disk errors)"
			log show --last 1d --style syslog --predicate 'process == "irondivid" OR (process == "kernel" AND (eventMessage CONTAINS[c] "jetsam" OR eventMessage CONTAINS[c] "memorystatus" OR eventMessage CONTAINS[c] "I/O error"))' 2>&1 | tail -n 2000
		fi
	fi
} | put kernel/kernel.txt

chmod -R go-rwx "$OUT" 2>/dev/null

# ------------------------------------------------------------ output
if [ "$SHAR" = 1 ]; then
	say "diag.sh: writing the folder to stdout as a shell archive (not redacted)"
	echo "#!/bin/sh"
	echo "# irondivi diag.sh shell archive: NOT REDACTED. Unpack with sh in an empty"
	echo "# folder made under umask 077, then run irondivi-cli diag --import on it."
	echo "umask 077"
	echo "set -e"
	(cd "$OUT" && find . -type f) | sed 's|^\./||' | while IFS= read -r f; do
		case $f in *"'"*|/*|*..*) say "diag.sh: skipped a file with an unsafe name"; continue ;; esac
		echo "mkdir -p './$(dirname "$f")'"
		echo ": > './$f'"
		od -An -v -to1 "$OUT/$f" | awk -v f="$f" '
			{ for (i = 1; i <= NF; i++) { s = s "\\" $i; c++ } }
			c >= 512 { printf "printf %c%s%c >> %c./%s%c\n", 39, s, 39, 39, f, 39; s = ""; c = 0 }
			END { if (c) printf "printf %c%s%c >> %c./%s%c\n", 39, s, 39, 39, f, 39 }'
	done
	if [ "$TMPOUT" = 1 ]; then
		rm -rf "$OUT"
	fi
	say "diag.sh: on the receiving side: mkdir -m 700 d && (cd d && umask 077 && sh) < archive"
	say "  then run: irondivi-cli diag --import d"
else
	say "diag.sh: wrote $OUT (mode 0700)."
	say "It is NOT redacted: it may hold user names, paths, addresses and IPs. Do not send it as it is."
	say "Run \`irondivi-cli diag --import $OUT\` on any machine where irondivi-cli runs to review and send it."
fi
