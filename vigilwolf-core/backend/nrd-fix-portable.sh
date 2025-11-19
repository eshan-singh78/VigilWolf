#!/usr/bin/env bash
# Don't exit on error - we want to try all days even if some fail
set +e

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
    
    # Download with error handling
    if ! curl -L "$URL" -o "$ZIP_FILE" 2>/dev/null; then
        echo -e "${RED}Failed to download NRD for $TODAY - skipping${RESET}"
        continue
    fi
    
    # Check if file is actually a valid zip
    if [ ! -s "$ZIP_FILE" ]; then
        echo -e "${RED}Downloaded file is empty for $TODAY - skipping${RESET}"
        rm -f "$ZIP_FILE"
        continue
    fi

    echo -e "${GREEN}Extracting $ZIP_FILE ...${RESET}"
    mkdir -p "$EXTRACT_DIR"
    
    # Try to unzip with error handling
    if ! unzip -o "$ZIP_FILE" -d "$EXTRACT_DIR" 2>/dev/null; then
        echo -e "${RED}Failed to extract $ZIP_FILE (corrupted or invalid) - skipping${RESET}"
        rm -f "$ZIP_FILE"
        continue
    fi

    # Only append if domain-names.txt exists
    if find "$EXTRACT_DIR" -type f -name "domain-names.txt" -exec false {} +; then
        echo -e "${RED}No domain-names.txt found for $TODAY - skipping${RESET}"
    else
        find "$EXTRACT_DIR" -type f -name "domain-names.txt" -exec cat {} + >> "$MERGED_FILE"
        echo -e "${GREEN}Successfully added domains from $TODAY${RESET}"
    fi
done

echo -e "${CYAN}------------------------------------------${RESET}"

# Check if we got any domains
DOMAIN_COUNT=$(grep -v "^#" "$MERGED_FILE" | grep -v "^$" | wc -l | tr -d ' ')
if [ "$DOMAIN_COUNT" -eq 0 ]; then
    echo -e "${RED}WARNING: No domains were successfully downloaded!${RESET}"
    echo -e "${RED}All NRD sources failed or were unavailable.${RESET}"
else
    echo -e "${GREEN}Static merged file done: $MERGED_FILE (${DOMAIN_COUNT} domains)${RESET}"
fi

# ---------------------------
# Folder for timestamped dumps
# ---------------------------
DUMP_DIR="$ROOT_DIR/nrd-file-dump"
mkdir -p "$DUMP_DIR"

TIMESTAMP=$(date -u "+%Y-%m-%d_%H-%M-%S")
TIMESTAMPED_FILE="$DUMP_DIR/nrd-${TIMESTAMP}.txt"
echo "# Timestamped NRD merge: $TIMESTAMP" > "$TIMESTAMPED_FILE"

TIMESTAMPED_COUNT=0
for dir in "$TEMP_DIR"/*/; do
    [ -d "$dir" ] || continue
    FILE="$dir/domain-names.txt"
    if [ -f "$FILE" ]; then
        echo -e "${CYAN}Adding domains from $(basename "$dir")${RESET}"
        echo "# Domains from $(basename "$dir")" >> "$TIMESTAMPED_FILE"
        cat "$FILE" >> "$TIMESTAMPED_FILE"
        echo "" >> "$TIMESTAMPED_FILE"
        TIMESTAMPED_COUNT=$((TIMESTAMPED_COUNT + 1))
    fi
done

if [ "$TIMESTAMPED_COUNT" -eq 0 ]; then
    echo -e "${RED}No timestamped file created - no valid data available${RESET}"
    rm -f "$TIMESTAMPED_FILE"
    echo -e "${RED}All NRD downloads failed. This may be temporary - try again later.${RESET}"
    exit 1
else
    echo -e "${GREEN}Timestamped merged file created: $TIMESTAMPED_FILE${RESET}"
fi

echo -e "${CYAN}Temporary files remain in: $TEMP_DIR${RESET}"
echo -e "${CYAN}All timestamped files are in folder: $DUMP_DIR${RESET}"

# Exit successfully if we got at least some data
exit 0
