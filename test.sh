#!/bin/sh
csv_file="keepass.csv"
json_file="keepass.json"
tmp_file="/tmp/csv-importer__test.json"

if [ -f "$csv_file" ] && [ -f "$json_file" ]; then
  python csv-importer.py \
    --no-rest \
    --csv "$csv_file" \
    --json "$tmp_file" \
    --escapechar '\'
  if [ $(diff "$tmp_file" "$json_file" | wc -c) -eq 0 ]; then
    exit_code=0
    echo "Test passed, keepass.csv produced expected output."
  else
    exit_code=1
    echo "Test failed, keepass.csv produced unexpected output."
    diff "$tmp_file" "$json_file"
  fi
  rm $tmp_file
  exit $exit_code
fi
