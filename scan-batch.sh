#!/bin/bash
# Scan a repo and output summary
REPO="$1"
cd ~/clawd/dockervet-dev

RESULT=$(node dist/index.js --github "$REPO" --format json 2>/dev/null)

python3 -c "
import json,sys
from collections import Counter

data = json.loads('''$RESULT''') if '''$RESULT'''.strip() else []
if not isinstance(data, list):
    data = []

files = set()
sev = {'error':0,'warning':0,'info':0,'style':0}
findings = []
for i in data:
    files.add(i.get('file',''))
    s = i.get('severity','info')
    sev[s] = sev.get(s,0) + 1
    findings.append(f\"{i['rule']}: {i['message'][:100]}\")

print(f'repo=$REPO')
print(f'files={len(files)}')
print(f'errors={sev[\"error\"]} warnings={sev[\"warning\"]} info={sev[\"info\"]} style={sev[\"style\"]}')
print(f'total={sum(sev.values())}')

rules = Counter(i.split(':')[0] for i in findings)
print('top_rules:')
for r,c in rules.most_common(10):
    print(f'  {r}: {c}x')
"
