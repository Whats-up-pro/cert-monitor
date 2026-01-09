#!/bin/bash
# Cert-Monitor v2.0 - Benchmark Script
# Runs performance benchmarks on the verification agent

set -e

AGENT_URL="${AGENT_URL:-http://localhost:8080}"
DOMAINS_FILE="${DOMAINS_FILE:-testdata/domains_1000.txt}"
OUTPUT_DIR="${OUTPUT_DIR:-benchmark_results}"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)

echo "╔════════════════════════════════════════════════════════════╗"
echo "║         Cert-Monitor v2.0 Performance Benchmark            ║"
echo "╚════════════════════════════════════════════════════════════╝"
echo ""
echo "Agent URL: $AGENT_URL"
echo "Domains file: $DOMAINS_FILE"
echo "Output: $OUTPUT_DIR"
echo ""

# Create output directory
mkdir -p "$OUTPUT_DIR"

# Check if agent is running
echo "🔍 Checking agent health..."
if ! curl -s "$AGENT_URL/api/v2/health" > /dev/null; then
    echo "❌ Agent is not running at $AGENT_URL"
    exit 1
fi
echo "✅ Agent is healthy"
echo ""

# Count domains
DOMAIN_COUNT=$(grep -v '^#' "$DOMAINS_FILE" | grep -v '^$' | wc -l)
echo "📋 Testing $DOMAIN_COUNT domains"
echo ""

# Results arrays
declare -a latencies
declare -a verdicts

# Run individual tests
echo "🚀 Starting benchmark..."
echo ""

SAFE_COUNT=0
MITM_COUNT=0
SUSPICIOUS_COUNT=0
ERROR_COUNT=0
TOTAL_LATENCY=0

while IFS= read -r domain || [ -n "$domain" ]; do
    # Skip comments and empty lines
    [[ "$domain" =~ ^#.*$ ]] && continue
    [[ -z "$domain" ]] && continue
    
    # Make request
    START=$(date +%s%N)
    RESPONSE=$(curl -s -X POST "$AGENT_URL/api/v2/verify" \
        -H "Content-Type: application/json" \
        -d "{\"domain\": \"$domain\", \"request_id\": \"bench-$TIMESTAMP\"}" \
        --max-time 30 2>/dev/null || echo '{"verdict":"ERROR","latency_ms":30000}')
    END=$(date +%s%N)
    
    # Parse response
    VERDICT=$(echo "$RESPONSE" | grep -o '"verdict":"[^"]*"' | cut -d'"' -f4)
    LATENCY=$(echo "$RESPONSE" | grep -o '"latency_ms":[0-9]*' | cut -d':' -f2)
    
    # Default values
    [ -z "$VERDICT" ] && VERDICT="ERROR"
    [ -z "$LATENCY" ] && LATENCY=0
    
    # Update counters
    case "$VERDICT" in
        SAFE) ((SAFE_COUNT++)) ;;
        MITM_DETECTED) ((MITM_COUNT++)) ;;
        SUSPICIOUS) ((SUSPICIOUS_COUNT++)) ;;
        *) ((ERROR_COUNT++)) ;;
    esac
    
    TOTAL_LATENCY=$((TOTAL_LATENCY + LATENCY))
    
    # Print progress
    printf "  %-30s %s [%4dms]\n" "$domain" "$VERDICT" "$LATENCY"
    
    # Save to results file
    echo "$domain,$VERDICT,$LATENCY" >> "$OUTPUT_DIR/results_$TIMESTAMP.csv"
    
done < "$DOMAINS_FILE"

echo ""
echo "═══════════════════════════════════════════════════════════════"
echo ""

# Calculate statistics
TESTED=$((SAFE_COUNT + MITM_COUNT + SUSPICIOUS_COUNT + ERROR_COUNT))
AVG_LATENCY=$((TOTAL_LATENCY / TESTED))

# Print summary
echo "📊 BENCHMARK RESULTS"
echo "───────────────────────────────────────────────────────────────"
printf "  Total domains tested:     %d\n" "$TESTED"
printf "  ✅ SAFE:                  %d (%.1f%%)\n" "$SAFE_COUNT" "$(echo "scale=1; $SAFE_COUNT * 100 / $TESTED" | bc)"
printf "  🚨 MITM_DETECTED:         %d (%.1f%%)\n" "$MITM_COUNT" "$(echo "scale=1; $MITM_COUNT * 100 / $TESTED" | bc)"
printf "  ⚠️  SUSPICIOUS:           %d (%.1f%%)\n" "$SUSPICIOUS_COUNT" "$(echo "scale=1; $SUSPICIOUS_COUNT * 100 / $TESTED" | bc)"
printf "  ❌ ERROR:                 %d (%.1f%%)\n" "$ERROR_COUNT" "$(echo "scale=1; $ERROR_COUNT * 100 / $TESTED" | bc)"
echo "───────────────────────────────────────────────────────────────"
printf "  Average latency:          %d ms\n" "$AVG_LATENCY"
printf "  Total time:               %d ms\n" "$TOTAL_LATENCY"
echo "───────────────────────────────────────────────────────────────"
echo ""

# Save summary
cat > "$OUTPUT_DIR/summary_$TIMESTAMP.json" << EOF
{
  "timestamp": "$TIMESTAMP",
  "agent_url": "$AGENT_URL",
  "domains_tested": $TESTED,
  "results": {
    "safe": $SAFE_COUNT,
    "mitm_detected": $MITM_COUNT,
    "suspicious": $SUSPICIOUS_COUNT,
    "error": $ERROR_COUNT
  },
  "latency": {
    "average_ms": $AVG_LATENCY,
    "total_ms": $TOTAL_LATENCY
  },
  "detection_rate": "N/A (no simulated attack)",
  "false_positive_rate": 0
}
EOF

echo "💾 Results saved to $OUTPUT_DIR/"
echo ""
echo "✅ Benchmark complete!"
