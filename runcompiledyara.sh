#!/bin/bash

COMPILED_DIR="Compiled_yara_rule"

if [ "$#" -lt 1 ]; then
    echo "Usage: $0 <target_file_or_directory>"
    exit 1
fi

TARGET="$1"

# Cek folder compiled rule
if [ ! -d "$COMPILED_DIR" ]; then
    echo "Error: $COMPILED_DIR not found!"
    exit 1
fi

# Siapkan list target file
TARGETS=()
if [ -f "$TARGET" ]; then
    TARGETS+=("$TARGET")
    REPORT_FILE="Report_scan_$(basename "$TARGET").txt"
elif [ -d "$TARGET" ]; then
    while IFS= read -r -d '' file; do
        TARGETS+=("$file")
    done < <(find "$TARGET" -type f -print0)
    REPORT_FILE="Report_scan_$(basename "$TARGET").txt"
else
    echo "Error: $TARGET is not a valid file or directory."
    exit 1
fi

> "$REPORT_FILE"  # Kosongkan laporan lama

# Scan dengan semua compiled rule
for RULE in "$COMPILED_DIR"/*; do
    if file "$RULE" | grep -q "YARA"; then
        echo "==> Scanning with rule: $(basename "$RULE")"
        for TGT in "${TARGETS[@]}"; do
            echo "--- Target: $TGT"
            MATCHES=$(yara -w --threads=32 -C "$RULE" "$TGT" 2>/dev/null)
            if [ -n "$MATCHES" ]; then
                echo "[FOUND] Rule: $(basename "$RULE") | Target: $TGT" >> "$REPORT_FILE"
                echo "$MATCHES" >> "$REPORT_FILE"
                echo "" >> "$REPORT_FILE"
                echo "$MATCHES"
            fi
        done
    else
        echo "Skipping non-YARA file: $RULE"
    fi
done

echo "Scan selesai. Lihat hasil di: $REPORT_FILE"
