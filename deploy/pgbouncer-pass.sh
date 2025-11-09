#!/usr/bin/env bash
# Usage: echo -n 'password' | ./pgbouncer_md5_line.sh username
set -eu

if [ $# -ne 1 ]; then
  printf 'Usage: %s USERNAME\nReads password from stdin and writes a pgbouncer userlist line.\n' "$0" >&2
  exit 2
fi

username="$1"

# Read entire stdin (password). Command-substitution strips trailing newlines.
password="$(cat -)"

# Compute MD5 of password + username. Support both common variants (md5sum or macOS md5).
if command -v md5sum >/dev/null 2>&1; then
  hash="$(printf '%s' "${password}${username}" | md5sum | cut -d' ' -f1)"
else
  # macOS: md5 -q prints only the digest
  hash="$(printf '%s' "${password}${username}" | md5 -q)"
fi

# Output the line in pgbouncer userlist.txt format
printf '"%s" "md5%s"\n' "$username" "$hash"
