#!/usr/bin/env bash
# Fails if the upstream project's name appears anywhere in the tree except the licence and notice
# files (LICENSE, NOTICE, THIRD-PARTY*) and the git history. Checks file contents and file names,
# tracked and untracked, skipping .git and build output (target/, dist/). Built artifacts carry the
# licence notice on purpose; scripts/no-upstream-names.sh --artifact <file> checks one artifact for
# any other occurrence. scripts/no-upstream-names.sh --files <file>... checks just those files.
set -u
cd "$(dirname "$0")/.."
if [ "${1:-}" = "--files" ]; then
  # Checks only the named files (contents and names) with the same pattern; used by scripts/image-check.sh.
  shift
  bad=0
  for f in "$@"; do
    if printf '%s' "$f" | grep -Eiq "$(printf 'fl%s|hector%s' 'oci' 'vent')"; then echo "name in file name: $f"; bad=1; fi
    if grep -Eiqs "$(printf 'fl%s|hector%s' 'oci' 'vent')" -- "$f"; then echo "name in contents: $f"; bad=1; fi
  done
  exit "$bad"
fi
if [ "${1:-}" = "--artifact" ]; then
  # An artifact legitimately holds the licence text once. Any other occurrence is a leak.
  f="${2:?usage: --artifact <file>}"
  n=$(strings -a "$f" | grep -Eio "$(printf 'fl%s|hector%s' 'oci' 'vent')" | wc -l | tr -d ' ')
  lic=$(strings -a "$f" | grep -c "Copyright (c) 2025 Fl" || true)
  echo "occurrences in $f: $n (licence copyright lines: $lic)"
  strings -a "$f" | grep -Ein "$(printf 'fl%s|hector%s' 'oci' 'vent')" | grep -v "Copyright (c) 2025\|Portions copyright" | head -20
  exit 0
fi
# The names are assembled here so this script does not contain them literally.
PATTERN="$(printf 'fl%s|hector%s' 'oci' 'vent')"
ALLOWED='(^|/)(LICENSE|NOTICE|THIRD-PARTY[^/]*)$'
fail=0

while IFS= read -r -d '' f; do
  f="${f#./}"
  if [[ "$f" =~ $ALLOWED ]]; then continue; fi
  if printf '%s' "$f" | grep -Eiq "$PATTERN"; then
    echo "name in file name: $f"; fail=1
  fi
  if grep -Eiqs "$PATTERN" -- "$f" 2>/dev/null; then
    echo "name in contents: $f"; grep -Eins "$PATTERN" -- "$f" | head -3; fail=1
  fi
done < <(find . \( -path ./.git -o -path ./target -o -path ./dist -o -path ./native \) -prune -o -type f -print0)

if [ "$fail" -ne 0 ]; then
  echo "FAIL: the upstream name appears outside LICENSE, NOTICE and THIRD-PARTY files."
  exit 1
fi
echo "OK: no upstream names outside LICENSE, NOTICE and THIRD-PARTY files."
