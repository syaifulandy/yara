#!/bin/bash

RULE_DIR="yara-rules"
echo -n "Masukkan path file target memory dump (.dmp): "
read TARGET

RULES=("$RULE_DIR"/*.yar)
TOTAL=${#RULES[@]}
COUNT=0

for rule in "${RULES[@]}"; do
    ((COUNT++))
    echo "[$COUNT/$TOTAL] Scanning with: $rule"
    yara -w --threads=32 "$rule" "$TARGET"
done
