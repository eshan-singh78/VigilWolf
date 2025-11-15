#!/usr/bin/env bash

set -e

# ------------------------------------------------------------------------------
# COLOR HELPERS
# ------------------------------------------------------------------------------
echo_red()   { printf "\033[31m%s\033[0m\n" "$*"; }
echo_green() { printf "\033[32m%s\033[0m\n" "$*"; }
echo_cyan()  { printf "\033[36m%s\033[0m\n" "$*"; }
error() { echo_red "$@"; exit 1; }

# ------------------------------------------------------------------------------
# CHECK COMMANDS
# ------------------------------------------------------------------------------
for cmd in mkdir wc base64 curl cat date tr; do
    command -v "$cmd" >/dev/null 2>&1 || error "Missing command: $cmd"
done

# Detect decompressor
if command -v zcat >/dev/null 2>&1; then
    ZCAT="zcat"
elif command -v gzcat >/dev/null 2>&1; then
    ZCAT="gzcat"
else
    error "Neither zcat nor gzcat found!"
fi

# ------------------------------------------------------------------------------
# SCRIPT DIR (portable)
# ------------------------------------------------------------------------------
SCRIPT="$0"
case "$SCRIPT" in
    /*) DIR=$(dirname "$SCRIPT") ;;
    *)  DIR=$(cd "$(dirname "$SCRIPT")" && pwd) ;;
esac

# ------------------------------------------------------------------------------
# CONFIG
# ------------------------------------------------------------------------------
DAY_RANGE="${DAY_RANGE:-7}"
DAILY_DIR="${DAILY_DIR:-daily}"

# Portable mktemp
TEMP_FILE=$(mktemp -t nrdtemp)

BASE_URL_FREE="https://whoisds.com/whois-database/newly-registered-domains"

COMMENT="# NRD list generated on $(date '+%Y-%m-%d'), source: WhoisDS.com"

echo_green "Using universal NRD downloader..."
echo_cyan "Fetching last $DAY_RANGE days..."

echo "$COMMENT" >> "$TEMP_FILE"

mkdir -p "$DIR/$DAILY_DIR/free"

# ------------------------------------------------------------------------------
# PORTABLE DATE
# ------------------------------------------------------------------------------
portable_date() {
    local days_ago="$1"

    # GNU (Linux)
    d=$(date -u -d "$days_ago days ago" "+%Y-%m-%d" 2>/dev/null)
    [ -n "$d" ] && { echo "$d"; return; }

    # BSD/macOS
    d=$(date -u -v-"$days_ago"d "+%Y-%m-%d" 2>/dev/null)
    [ -n "$d" ] && { echo "$d"; return; }

    # fallback
    d=$(date -u "+%Y-%m-%d")
    echo "$d"
}

# ------------------------------------------------------------------------------
# DOWNLOAD FREE LIST
# ------------------------------------------------------------------------------
download_free() {
    echo_cyan "Downloading free NRD list..."

    local i=$DAY_RANGE

    while [ "$i" -gt 0 ]; do
        DATE=$(portable_date "$i")
        FILE="$DIR/$DAILY_DIR/free/$DATE"

        if [ -s "$FILE" ]; then
            echo_cyan "$FILE exists, skipping..."
        else
            printf "Downloading %s ... " "$DATE"

            encoded=$(printf "%s" "${DATE}.zip" | base64)
            short="${encoded%?}"
            URL="${BASE_URL_FREE}/${short}/nrd"

            curl -sSLo- "$URL" | $ZCAT 2>/dev/null | tr -d '\015' > "$FILE"

            echo "" >> "$FILE"
            echo "$(grep -vc '^$' "$FILE") domains."
        fi

        echo "# ${DATE} NRD start" >> "$TEMP_FILE"
        cat "$FILE" >> "$TEMP_FILE"
        echo "# ${DATE} NRD end" >> "$TEMP_FILE"

        i=$((i-1))
    done

    echo "$COMMENT" >> "$TEMP_FILE"

    mv "$TEMP_FILE" "$DIR/nrd-${DAY_RANGE}days-free.txt"
    chmod +r "$DIR/nrd-${DAY_RANGE}days-free.txt"

    echo_green "Saved: nrd-${DAY_RANGE}days-free.txt"
}

download_free
