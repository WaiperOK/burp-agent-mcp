#!/usr/bin/env bash
# Runs every test suite. Browser tests need Chromium (playwright install chromium).
# Interpreter: $PYTHON if set, else ./.venv/bin/python if present, else python3.
cd "$(dirname "$0")" || exit 1

if [ -n "${PYTHON:-}" ]; then
  PY="$PYTHON"
elif [ -x ./.venv/bin/python ]; then
  PY=./.venv/bin/python
else
  PY=python3
fi

status=0
for t in tests/test_*.py; do
  printf '== %s\n' "$t"
  out=$($PY "$t" 2>&1)
  rc=$?
  printf '%s\n' "$out" | tail -3
  [ "$rc" -eq 0 ] || status=1
done
exit $status
