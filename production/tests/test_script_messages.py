#!/usr/bin/env python3
"""Every message that stops the deploymentScript goes to stderr.

The portal's error banner shows only what the script wrote to stderr. A failure
message on stdout ends up in the script's Logs tab and the banner reads "the
script failed without returning any errors".
"""

import json
import os
import re
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
TEMPLATE = os.path.join(os.path.dirname(HERE), "azuredeploy.json")

tmpl = json.load(open(TEMPLATE))
script = [r for r in tmpl["resources"] if r.get("type", "").endswith("deploymentScripts")][0]["properties"]["scriptContent"]

failures = []
checks = 0

exits = [m.start() for m in re.finditer(r"exit 1", script)]
check_msg = "at least the download, zip, settings, storage, pointer and index failures must be found"
checks += 1
if len(exits) < 6:
    failures.append(check_msg + f" (found {len(exits)} exit 1)")

for pos in exits:
    before = script[max(0, pos - 220):pos]
    # the statement right before `exit 1` must be the message itself, redirected: echo '...' >&2;  or  echo "..." >&2;
    # (a bare `echo >&2` after a stdout message would pass a weaker check)
    stmt = before.rsplit("echo ", 1)[-1] if "echo " in before else ""
    checks += 1
    if not re.search(r"""^(?:'[^']+'|"[^"]+")\s*>&2\s*;?\s*$""", stmt):
        failures.append("exit 1 not preceded by an echo to stderr: ..." + before[-90:].replace("\n", " "))

if failures:
    for f in failures:
        print("FAIL:", f)
    sys.exit(1)
print(f"deploymentScript failure messages go to stderr: OK ({checks} checks)")
