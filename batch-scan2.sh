#!/bin/bash
cd ~/clawd/dockervet-dev
export GITHUB_TOKEN=$(gh auth token)

REPOS=(
  "overleaf/overleaf"
  "jellyfin/jellyfin"
  "teable-group/teable"
  "pocketbase/pocketbase"
  "astral-sh/uv"
  "juspay/hyperswitch"
  "surrealdb/surrealdb"
  "leptos-rs/leptos"
)

parse_results() {
python3 -c "
import json,sys
try:
    data=json.load(sys.stdin)
except:
    print('NO OUTPUT / PARSE ERROR')
    return
if not isinstance(data, list):
    data = [data]
sev = {'error':0,'warning':0,'info':0,'style':0}
rules = {}
files_set = set()
for item in data:
    if isinstance(item, dict) and 'file' in item and 'rule' in item:
        s = item.get('severity','unknown')
        sev[s] = sev.get(s,0)+1
        r = item.get('rule','')
        files_set.add(item.get('file',''))
        if r not in rules:
            rules[r] = {'count':0, 'msg': item.get('message','')[:100]}
        rules[r]['count'] += 1
total = sum(sev.values())
print(f'Files: {len(files_set)}, Total findings: {total}')
print(f'  error={sev[\"error\"]}, warning={sev[\"warning\"]}, info={sev[\"info\"]}, style={sev[\"style\"]}')
print('Top rules:')
for r in sorted(rules, key=lambda x:-rules[x]['count'])[:8]:
    print(f'  {r}: {rules[r][\"count\"]}x - {rules[r][\"msg\"]}')
" 2>&1
}

for repo in "${REPOS[@]}"; do
  echo "=== Scanning: $repo ==="
  node dist/index.js --github "$repo" --format json 2>/dev/null | parse_results
  echo ""
done
