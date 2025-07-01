#!/bin/bash

if [[ $# -ne 1 ]]; then
  echo "Usage: $0 <Report_scan_yara_.txt>"
  exit 1
fi

INPUT_TEXT="$1"
BASENAME_INPUT=$(basename "$INPUT_TEXT" .txt | sed 's/Report_scan_dump_memory_//')
INTERMEDIATE_CSV="target_md5_${BASENAME_INPUT}.csv"
FINAL_CSV="hasil_virustotal_${BASENAME_INPUT}.csv"
API_KEY_FILE="api_key_virtot.txt"

# Validasi file input
if [[ ! -f "$INPUT_TEXT" ]]; then
  echo "[ERROR] File input tidak ditemukan: $INPUT_TEXT"
  exit 2
fi

# Validasi file API key
if [[ ! -f "$API_KEY_FILE" ]]; then
  echo "[ERROR] File $API_KEY_FILE tidak ditemukan. Harap buat file ini dan masukkan API key Anda di dalamnya."
  exit 3
fi

API_KEY=$(<"$API_KEY_FILE")

# Tahap 1: Ekstrak Target dan Hitung MD5
> "$INTERMEDIATE_CSV"

# Gabungkan semua path dari baris Target dan baris rule lainnya, lalu hilangkan duplikat
TARGETS=$( (grep -oP 'Target:\s+\K.*' "$INPUT_TEXT"; grep -v '^\[FOUND\]' "$INPUT_TEXT" | awk '{print $NF}') | sort -u )

while read -r TARGET; do
  [[ -z "$TARGET" ]] && continue  # lewati jika kosong
  if [[ -f "$TARGET" ]]; then
    MD5=$(md5sum "$TARGET" | awk '{print $1}')
    echo "$TARGET,$MD5" >> "$INTERMEDIATE_CSV"
  else
    echo "[WARNING] File tidak ditemukan: Compiled_rule_fsyara_PE-ELFs | Target: $TARGET" >&2
  fi
done <<< "$TARGETS"

# Tahap 2: Cek ke VirusTotal
echo "target,md5,name,malicious,undetected,yara_rules,threat_names,threat_categories" > "$FINAL_CSV"

# Ambil hanya baris dengan md5 unik
awk -F, '!seen[$2]++' "$INTERMEDIATE_CSV" | while IFS=, read -r TARGET MD5; do
  echo "[$(date '+%H:%M:%S')] Cek: $TARGET ($MD5)"

  RESPONSE=$(curl -s --request GET "https://www.virustotal.com/api/v3/files/$MD5" \
       --header "accept: application/json" \
       --header "x-apikey: $API_KEY")

  echo "$RESPONSE" > "response_${MD5}.json"

  echo "$RESPONSE" | jq -r --arg target "$TARGET" '
    if .data then
      [
        $target,
        .data.attributes.md5 // "-",
        .data.attributes.meaningful_name // "-",
        .data.attributes.last_analysis_stats.malicious // 0,
        .data.attributes.last_analysis_stats.undetected // 0,
        (.data.attributes.crowdsourced_yara_results // [] | map(.rule_name) | join(";")),
        (.data.attributes.popular_threat_classification.popular_threat_name // [] | map(.value) | join(";")),
        (.data.attributes.popular_threat_classification.popular_threat_category // [] | map(.value) | join(";"))
      ]
    else
      [$target, "-", "-", "-", "-", "-", "-", "-"]
    end | @csv' >> "$FINAL_CSV"

  sleep 15

done
