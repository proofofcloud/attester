#!/bin/bash

set -e

if [ -z "$1" ] || [ -z "$2" ]; then
    echo "Verify ProofOfCloud attester results against a challenge"
    echo "Usage: $0 <results-file> <challenge>"
    echo "Example: $0 attester.results.txt beefdeed"
    exit 1
fi

RESULTS_FILE="$1"
CHALLENGE="$2"

if [ ! -f "$RESULTS_FILE" ]; then
    echo "Error: File '$RESULTS_FILE' not found"
    exit 1
fi

QUOTE=$(grep "^RAW Quote:" "$RESULTS_FILE" | cut -d' ' -f3)

if [ -z "$QUOTE" ]; then
    echo "Error: Could not extract quote from '$RESULTS_FILE'"
    exit 1
fi

OUTPUT=$(docker run \
    --rm \
    ghcr.io/proofofcloud/attester@sha256:2ae052dd244ab12880bf7a77b6580a289761d10bb19764310e4c44bbd8c5f14c \
    check "$QUOTE" 2>/dev/null)

if echo "$OUTPUT" | grep -q "Verification status: OK"; then
    QUOTE_VALID="yes"
else
    QUOTE_VALID="no"
fi

REPORT_DATA=$(echo "$OUTPUT" | grep "report_data = " | awk '{print $3}')
REPORT_DATA_TRIMMED=$(echo "$REPORT_DATA" | sed 's/0*$//')

CHALLENGE_UPPER=$(echo "$CHALLENGE" | tr '[:lower:]' '[:upper:]')
REPORT_DATA_UPPER=$(echo "$REPORT_DATA_TRIMMED" | tr '[:lower:]' '[:upper:]')

if [ "$CHALLENGE_UPPER" = "$REPORT_DATA_UPPER" ]; then
    CHALLENGE_MATCH="yes"
else
    CHALLENGE_MATCH="no"
fi

MACHINE_ID=$(echo "$OUTPUT" | grep "Machine-ID:" | awk '{print $2}' | tr '[:upper:]' '[:lower:]')

echo "quote_valid: $QUOTE_VALID"
echo "challenge_match: $CHALLENGE_MATCH"
echo "machine_id: $MACHINE_ID"


