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
# Today's date
# ---------------------------
TODAY=$(date -u "+%Y-%m-%d")

# ---------------------------
# NRD URL for today
# ---------------------------
DATE_B64=$(echo -n "${TODAY}.zip" | base64)
DATE_B64=${DATE_B64%=*}  # Remove trailing "="

URL="https://www.whoisds.com//whois-database/newly-registered-domains/${DATE_B64}/nrd"

# ---------------------------
# File names in temp folder
# ---------------------------
ZIP_FILE="$TEMP_DIR/${TODAY}.zip"
EXTRACT_DIR="$TEMP_DIR/${TODAY}"

# ---------------------------
# Download
# ---------------------------
echo "Downloading NRD for today: $TODAY ..."
curl -L "$URL" -o "$ZIP_FILE"

# ---------------------------
# Extract
# ---------------------------
echo "Extracting $ZIP_FILE ..."
mkdir -p "$EXTRACT_DIR"
unzip -o "$ZIP_FILE" -d "$EXTRACT_DIR"

echo "Done! NRD saved in $ZIP_FILE and extracted to $EXTRACT_DIR"
