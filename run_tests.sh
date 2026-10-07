#!/usr/bin/env bash
# Runs all gateway test suites. Browser tests need Chromium (playwright install chromium).
cd "$(dirname "$0")" || exit 1
PY=./.venv/bin/python
status=0
for t in tests/test_*.py; do
  printf '== %s\n' "$t"
  out=$($PY "$t" 2>&1)
  rc=$?
  printf '%s\n' "$out" | tail -3
  [ "$rc" -eq 0 ] || status=1
done
exit $status
