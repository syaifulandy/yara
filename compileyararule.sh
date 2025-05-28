#!/bin/bash

# Cek input
if [ $# -ne 2 ]; then
  echo "Usage: $0 <lokasi_rule_yara> <nama_compiled_rule>"
  exit 1
fi

RULE_DIR="$1"
OUTPUT_COMPILED="Compiled_rule_$2"

# Filter dan gabungkan rule .yar yang tidak mengandung 'filename', 'filepath', atau 'extension'
find "$RULE_DIR" -type f -name "*.yar" \
  ! -exec grep -q 'filename\|filepath\|extension' {} \; \
  -exec cat {} + > temp_all_rules.yar

# Kompilasi ke format .yarc
yarac temp_all_rules.yar "$OUTPUT_COMPILED"

# Opsional: hapus file sementara
rm temp_all_rules.yar

echo "Compiled YARA rules saved to $OUTPUT_COMPILED"
