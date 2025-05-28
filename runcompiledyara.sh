#!/bin/bash

if [ "$#" -ne 2 ]; then
    echo "Usage: $0 <compiled_rules.yarc> <target_file.dmp>"
    exit 1
fi

COMPILED_RULE="$1"
TARGET="$2"

echo "Scanning with compiled rules: $COMPILED_RULE"
yara -w --threads=32 -C "$COMPILED_RULE" "$TARGET"
