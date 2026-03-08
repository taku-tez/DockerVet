#!/bin/bash
# Batch scan script for DockerVet OSS scan
cd ~/clawd/dockervet-dev

REPOS=(
    "denoland/deno_docker"
    "elixir-lang/docker-elixir"
    "kubeshark/kubeshark"
    "pocketbase/pocketbase"
    "zammad/zammad-docker-compose"
    "mattermost/docker"
    "gleam-lang/gleam"
    "hadolint/language-docker"
    "kasmtech/workspaces-core-images"
    "unifi-poller/unpoller"
)

for repo in "${REPOS[@]}"; do
    echo "=== SCANNING: $repo ==="
    output=$(node dist/index.js --github "$repo" --format json 2>/dev/null)
    if [ -z "$output" ]; then
        echo "  No output (no Dockerfiles or error)"
        echo "---"
        continue
    fi
    echo "$output" | python3 << 'PYEOF'
import json,sys
try:
    data=json.load(sys.stdin)
    if not isinstance(data, list):
        print("  Unexpected format")
        sys.exit(0)
    # Count by severity
    sev={"error":0,"warning":0,"info":0,"style":0}
    files=set()
    rules={}
    for item in data:
        files.add(item.get("file",""))
        s=item.get("severity","info")
        sev[s]=sev.get(s,0)+1
        r=item.get("rule","?")
        rules[r]=rules.get(r,0)+1
    print("  Files: %d, Total: %d (E:%d W:%d I:%d S:%d)" % (len(files),len(data),sev["error"],sev["warning"],sev["info"],sev["style"]))
    # Top rules
    top=sorted(rules.items(),key=lambda x:-x[1])[:8]
    print("  Top rules:", ", ".join("%s(%d)" % (r,c) for r,c in top))
    # Show some findings for FP analysis
    seen=set()
    for item in data:
        r=item.get("rule","?")
        if r not in seen and len(seen)<10:
            seen.add(r)
            msg=item.get("message","")[:100]
            print("  [%s] %s: %s" % (item.get("severity","?"), r, msg))
except Exception as ex:
    print("  Parse error:", ex)
PYEOF
    echo "---"
done
