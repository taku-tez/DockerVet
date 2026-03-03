#!/usr/bin/env python3
"""Analyze DockerVet JSON output from stdin."""
import json, sys
from collections import Counter

data = json.load(sys.stdin)
if not isinstance(data, list):
    data = []

files = set()
sev = {'error':0,'warning':0,'info':0,'style':0}
findings = []
for i in data:
    files.add(i.get('file',''))
    s = i.get('severity','info')
    sev[s] = sev.get(s,0) + 1
    findings.append(f"{i['rule']}: {i['message'][:100]}")

print(f"files={len(files)} errors={sev['error']} warnings={sev['warning']} info={sev['info']} style={sev['style']} total={sum(sev.values())}")

rules = Counter(i.split(':')[0] for i in findings)
print("top_rules:")
for r,c in rules.most_common(10):
    print(f"  {r}: {c}x")

# Print unique findings for FP analysis
print("\nunique_findings:")
seen = set()
for i in data:
    key = f"{i['rule']}|{i['message'][:80]}"
    if key not in seen:
        seen.add(key)
        print(f"  [{i['severity']}] {i['rule']}: {i['message'][:120]}")
