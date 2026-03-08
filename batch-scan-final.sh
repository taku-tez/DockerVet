#!/bin/bash
export GITHUB_TOKEN=$(gh auth token)
cd ~/clawd/dockervet-dev

REPOS=(
    "teamhanko/hanko"
    "paralus/paralus"
    "imgproxy/imgproxy"
    "MaterializeInc/materialize"
    "cloudnative-pg/cloudnative-pg"
    "apache/openwhisk"
    "flomesh-io/pipy"
)

for repo in "${REPOS[@]}"; do
    echo "=== SCANNING: $repo ==="
    node dist/index.js --github "$repo" --format json 2>/tmp/dv-err.log > /tmp/dv-out.json
    
    if [ ! -s /tmp/dv-out.json ]; then
        echo "  No output. Stderr: $(cat /tmp/dv-err.log | head -3)"
        echo "---"
        continue
    fi
    
    python3 << 'PYEOF'
import json
try:
    with open("/tmp/dv-out.json") as f:
        data=json.load(f)
    if not isinstance(data, list) or len(data)==0:
        print("  No findings")
    else:
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
        top=sorted(rules.items(),key=lambda x:-x[1])[:10]
        print("  Top rules:", ", ".join("%s(%d)" % (r,c) for r,c in top))
        seen=set()
        for item in data:
            r=item.get("rule","?")
            if r not in seen and len(seen)<15:
                seen.add(r)
                msg=item.get("message","")[:130]
                print("  [%s] %s: %s" % (item.get("severity","?"), r, msg))
except Exception as ex:
    print("  Parse error:", ex)
PYEOF
    echo "---"
done
