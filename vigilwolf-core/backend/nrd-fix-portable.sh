#!/usr/bin/env bash
set -e

RED="\033[31m"
GREEN="\033[32m"
CYAN="\033[36m"
RESET="\033[m"

ROOT_DIR="$(cd "$(dirname "$0")" && pwd)"
TEMP_DIR="$ROOT_DIR/nrdtemp"
mkdir -p "$TEMP_DIR"
echo -e "${CYAN}Using temp folder: $TEMP_DIR${RESET}"

DAY_RANGE=7
MERGED_FILE="$ROOT_DIR/nrd-${DAY_RANGE}days-free.txt"
echo "# NRD list for the last $DAY_RANGE days" > "$MERGED_FILE"

for i in $(seq 0 $((DAY_RANGE-1))); do
    if date -u -v-"$i"d "+%Y-%m-%d" >/dev/null 2>&1; then
        TODAY=$(date -u -v-"$i"d "+%Y-%m-%d")
    else
        TODAY=$(date -u -d "$i days ago" "+%Y-%m-%d")
    fi

    DATE_B64=$(echo -n "${TODAY}.zip" | base64)
    DATE_B64=${DATE_B64%=*}
    URL="https://www.whoisds.com//whois-database/newly-registered-domains/${DATE_B64}/nrd"

    ZIP_FILE="$TEMP_DIR/${TODAY}.zip"
    EXTRACT_DIR="$TEMP_DIR/${TODAY}"

    echo -e "${CYAN}------------------------------------------${RESET}"
    echo -e "${GREEN}Downloading NRD for: $TODAY${RESET}"
    curl -L "$URL" -o "$ZIP_FILE"

    echo -e "${GREEN}Extracting $ZIP_FILE ...${RESET}"
    mkdir -p "$EXTRACT_DIR"
    unzip -o "$ZIP_FILE" -d "$EXTRACT_DIR"

    find "$EXTRACT_DIR" -type f -name "domain-names.txt" -exec cat {} + >> "$MERGED_FILE"
done

echo -e "${CYAN}------------------------------------------${RESET}"
echo -e "${GREEN}Static merged file done: $MERGED_FILE${RESET}"

# ---------------------------
# Folder for timestamped dumps
# ---------------------------
DUMP_DIR="$ROOT_DIR/nrd-file-dump"
mkdir -p "$DUMP_DIR"

TIMESTAMP=$(date -u "+%Y-%m-%d_%H-%M-%S")
TIMESTAMPED_FILE="$DUMP_DIR/nrd-${TIMESTAMP}.txt"
echo "# Timestamped NRD merge: $TIMESTAMP" > "$TIMESTAMPED_FILE"

for dir in "$TEMP_DIR"/*/; do
    [ -d "$dir" ] || continue
    FILE="$dir/domain-names.txt"
    if [ -f "$FILE" ]; then
        echo -e "${CYAN}Adding domains from $(basename "$dir")${RESET}"
        echo "# Domains from $(basename "$dir")" >> "$TIMESTAMPED_FILE"
        cat "$FILE" >> "$TIMESTAMPED_FILE"
        echo "" >> "$TIMESTAMPED_FILE"
    fi
done

echo -e "${GREEN}Timestamped merged file created: $TIMESTAMPED_FILE${RESET}"
echo -e "${CYAN}Temporary files remain in: $TEMP_DIR${RESET}"
echo -e "${CYAN}All timestamped files are in folder: $DUMP_DIR${RESET}"
