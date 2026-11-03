#!/usr/bin/env bash
# One-line runner: unit tests, then the nginx proof (needs docker). Add --browser for the headless-browser run.
set -e; cd "$(dirname "$0")"; node --test site.test.js; ./site-test.sh "$@"
