#!/bin/bash
# Decode TDX quote hex and extract measurements
set -eo pipefail

usage() {
    cat <<EOF
Usage: $0 <hex_quote>
       echo <hex_quote> | $0

Extracts MRTD, RTMR[0], RTMR[1], RTMR[2] from a TDX quote.

Example:
  $0 04000200810000...
  cat quote.hex | $0
EOF
    exit 1
}

# Get hex from argument or stdin
if [ -n "$1" ]; then
    QUOTE_HEX="$1"
elif [ ! -t 0 ]; then
    QUOTE_HEX=$(cat)
else
    usage
fi

# Remove any whitespace, newlines, 0x prefix
QUOTE_HEX=$(echo "$QUOTE_HEX" | tr -d ' \n\r' | sed 's/^0x//')

# Convert to binary
TMPFILE=$(mktemp)
trap "rm -f $TMPFILE" EXIT
echo "$QUOTE_HEX" | xxd -r -p > "$TMPFILE"

# TDX Quote V4 structure:
# - Header: 48 bytes (offset 0)
# - TD Quote Body: starts at offset 48
#   - Within TD Quote Body:
#     - TEE_TCB_SVN: 16 bytes (offset 0)
#     - MRSEAM: 48 bytes (offset 16)
#     - MRSIGNER_SEAM: 48 bytes (offset 64)
#     - SEAM_ATTRIBUTES: 8 bytes (offset 112)
#     - TD_ATTRIBUTES: 8 bytes (offset 120)
#     - XFAM: 8 bytes (offset 128)
#     - MRTD: 48 bytes (offset 136)
#     - MRCONFIGID: 48 bytes (offset 184)
#     - MROWNER: 48 bytes (offset 232)
#     - MROWNERCONFIG: 48 bytes (offset 280)
#     - RTMR[0]: 48 bytes (offset 328)
#     - RTMR[1]: 48 bytes (offset 376)
#     - RTMR[2]: 48 bytes (offset 424)
#     - RTMR[3]: 48 bytes (offset 472)
#     - REPORT_DATA: 64 bytes (offset 520)

# Absolute offsets from start of quote (Header=48 + TD Quote Body offsets)
MRTD_OFFSET=$((48 + 136))
RTMR0_OFFSET=$((48 + 328))
RTMR1_OFFSET=$((48 + 376))
RTMR2_OFFSET=$((48 + 424))
RTMR3_OFFSET=$((48 + 472))

echo "=== TDX Quote Measurements ==="
echo ""

MRTD=$(xxd -s $MRTD_OFFSET -l 48 -p "$TMPFILE" | tr -d '\n')
RTMR0=$(xxd -s $RTMR0_OFFSET -l 48 -p "$TMPFILE" | tr -d '\n')
RTMR1=$(xxd -s $RTMR1_OFFSET -l 48 -p "$TMPFILE" | tr -d '\n')
RTMR2=$(xxd -s $RTMR2_OFFSET -l 48 -p "$TMPFILE" | tr -d '\n')
RTMR3=$(xxd -s $RTMR3_OFFSET -l 48 -p "$TMPFILE" | tr -d '\n')

echo "MRTD:    0x$MRTD"
echo "RTMR[0]: 0x$RTMR0"
echo "RTMR[1]: 0x$RTMR1"
echo "RTMR[2]: 0x$RTMR2"
echo "RTMR[3]: 0x$RTMR3"

echo ""
echo "Command to add to allowlist:"
echo "  ./scripts/setup.sh add-image --mrtd 0x$MRTD --rtmr0 0x$RTMR0 --rtmr1 0x$RTMR1"
