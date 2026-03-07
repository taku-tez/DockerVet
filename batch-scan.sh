#!/bin/bash
export GITHUB_TOKEN=$(gh auth token)
cd ~/clawd/dockervet-dev

REPOS=(
  "vercel/next.js"
  "denoland/deno"
  "rustdesk/rustdesk"
  "miniflux/v2"
  "zammad/zammad"
  "listmonk/listmonk"
  "netbox-community/netbox-docker"
  "getzola/zola"
  "valkey-io/valkey"
  "duckdb/duckdb"
)

for repo in "${REPOS[@]}"; do
  echo "=== Scanning $repo ==="
  OUTPUT=$(node dist/index.js --github "$repo" --format json 2>&1)
  
  # Check for errors
  if echo "$OUTPUT" | grep -q "^Error:"; then
    echo "ERROR: $OUTPUT"
    continue
  fi
  
  # Check if empty array
  COUNT=$(echo "$OUTPUT" | jq 'length' 2>/dev/null)
  if [ "$COUNT" = "0" ] || [ -z "$COUNT" ]; then
    echo "No Dockerfiles found or empty results"
    echo "---"
    continue
  fi
  
  # Get unique files
  FILES=$(echo "$OUTPUT" | jq '[.[].file] | unique | length' 2>/dev/null)
  TOTAL=$(echo "$OUTPUT" | jq 'length' 2>/dev/null)
  
  # Count by severity
  ERRORS=$(echo "$OUTPUT" | jq '[.[] | select(.severity == "error")] | length' 2>/dev/null)
  WARNINGS=$(echo "$OUTPUT" | jq '[.[] | select(.severity == "warning")] | length' 2>/dev/null)
  INFOS=$(echo "$OUTPUT" | jq '[.[] | select(.severity == "info")] | length' 2>/dev/null)
  STYLE=$(echo "$OUTPUT" | jq '[.[] | select(.severity == "style")] | length' 2>/dev/null)
  
  # Top rules
  TOP_RULES=$(echo "$OUTPUT" | jq -r '[.[].rule] | group_by(.) | map({rule: .[0], count: length}) | sort_by(-.count) | .[:5] | map("\(.rule)(\(.count))") | join(", ")' 2>/dev/null)
  
  # All unique rules
  ALL_RULES=$(echo "$OUTPUT" | jq -r '[.[].rule] | unique | join(", ")' 2>/dev/null)
  
  # Check for potential FPs - show findings with their details
  echo "Files: $FILES | Total: $TOTAL | E:$ERRORS W:$WARNINGS I:$INFOS S:$STYLE"
  echo "Top rules: $TOP_RULES"
  echo "All rules: $ALL_RULES"
  
  # Show sample of each rule for FP analysis
  echo "--- Sample findings ---"
  echo "$OUTPUT" | jq -r 'group_by(.rule) | .[] | "\(.[0].rule) (\(length)x): \(.[0].message[:100])"' 2>/dev/null
  echo "---"
done
