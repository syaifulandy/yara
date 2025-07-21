#!/bin/bash

# Cek input
if [ $# -ne 2 ]; then
  echo "Usage: $0 <lokasi_rule_yara> <nama_compiled_rule>"
  exit 1
fi

RULE_DIR="$1"
OUTPUT_COMPILED="Compiled_rule_$2"
TEMP_RULES_FILE="temp_all_rules.yar"

# Hapus file lama jika ada
rm -f "$OUTPUT_COMPILED" "$TEMP_RULES_FILE"

# Gabungkan rule yang tidak mengandung identifier bermasalah
find "$RULE_DIR" -type f \( -name "*.yar" -o -name "*.yara" \) \
  ! -exec grep -q -E 'filename|filepath|extension|is__elf' {} \; \
  -exec sh -c 'echo "// From file: $1" >> '"$TEMP_RULES_FILE"'; cat "$1" >> '"$TEMP_RULES_FILE"'' _ {} \;


# Kompilasi ke format .yarac
echo "[*] Compiling filtered rules..."
if yarac "$TEMP_RULES_FILE" "$OUTPUT_COMPILED"; then
  echo "[✓] Compiled YARA rules saved to $OUTPUT_COMPILED"
else
  echo "[✗] Failed to compile. See syntax or identifier errors above."
  rm -f "$OUTPUT_COMPILED"
fi

# Bersih-bersih
#rm -f "$TEMP_RULES_FILE"
