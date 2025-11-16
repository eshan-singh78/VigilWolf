#!/usr/bin/env bash
set -e

# ---------------------------
# Script root directory
# ---------------------------
ROOT_DIR="$(cd "$(dirname "$0")" && pwd)"

# ---------------------------
# Temporary folder inside root
# ---------------------------
TEMP_DIR="$ROOT_DIR/nrdtemp"
mkdir -p "$TEMP_DIR"
echo "Using temp folder: $TEMP_DIR"

# ---------------------------
# Number of days to fetch
# ---------------------------
DAY_RANGE=7

# ---------------------------
# File to merge all domains
# ---------------------------
MERGED_FILE="$ROOT_DIR/nrd-${DAY_RANGE}days-free.txt"
echo "# NRD list for the last $DAY_RANGE days" > "$MERGED_FILE"

# ---------------------------
# Loop over past 7 days
# ---------------------------
for i in $(seq 0 $((DAY_RANGE-1))); do
    # Portable date calculation (macOS/GNU)
    if date -u -v-"$i"d "+%Y-%m-%d" >/dev/null 2>&1; then
        # macOS
        TODAY=$(date -u -v-"$i"d "+%Y-%m-%d")
    else
        # Linux/GNU
        TODAY=$(date -u -d "$i days ago" "+%Y-%m-%d")
    fi

    # Base64 encode date + ".zip"
    DATE_B64=$(echo -n "${TODAY}.zip" | base64)
    DATE_B64=${DATE_B64%=*}

    URL="https://www.whoisds.com//whois-database/newly-registered-domains/${DATE_B64}/nrd"

    ZIP_FILE="$TEMP_DIR/${TODAY}.zip"
    EXTRACT_DIR="$TEMP_DIR/${TODAY}"

    echo "------------------------------------------"
    echo "Downloading NRD for: $TODAY"
    curl -L "$URL" -o "$ZIP_FILE"

    echo "Extracting $ZIP_FILE ..."
    mkdir -p "$EXTRACT_DIR"
    unzip -o "$ZIP_FILE" -d "$EXTRACT_DIR"

    # Merge all domains into single file
    # Assuming extracted file contains domains in plain text
    # Find all files inside extracted folder and append
    find "$EXTRACT_DIR" -type f -exec cat {} + >> "$MERGED_FILE"

done

echo "------------------------------------------"
echo "Done! All NRD data for the past $DAY_RANGE days saved in $MERGED_FILE"
echo "Temporary downloads and extraction are in $TEMP_DIR"
