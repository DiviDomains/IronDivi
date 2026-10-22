#!/usr/bin/env bash
# One-line runner: unit tests, then the nginx proof (needs docker).
set -e; cd "$(dirname "$0")"; node --test . ; ./nginx-test.sh
