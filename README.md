# GPON Malware Framework Generator

A small Flask app that takes **already-completed** static and dynamic malware analysis
(notes, `strings`/`readelf` output, sandbox exports) and generates a consistent
**response and detection framework** for GPON/IoT malware.

It is a *framework generator*, not a malware analyzer: it never executes, unpacks or
emulates a sample. The analysis was done beforehand in FlareVM, REMnux and any.run;
this tool performs the "analysis of the analysis".

```
analysis notes / files ──► Flask  POST /api/generate ──► framework JSON ──► web page
                           (regex extraction + rules)                      (+ Markdown / JSON / PDF export)
```

## Run it

**Easiest:** install Python 3.10+ (tick *Add python.exe to PATH*), then double-click
**`run.bat`** (Windows) or run `sh run.sh` (macOS/Linux). The first run installs
everything automatically (needs internet, about 1 minute), then opens the browser at
http://127.0.0.1:5057.

Manual steps:

```bash
python -m venv .venv
.venv\Scripts\python -m pip install -r requirements-dev.txt  # Windows
.venv\Scripts\python app.py                                  # http://127.0.0.1:5057
.venv\Scripts\python -m pytest -q                            # regression tests
```

## Publish on GitHub Pages

`docs/` is a browser-only build of the same app: the engine is ported to JavaScript
(`docs/engine.js`) and runs inside the visitor's browser, so there is no server and
no analysis data ever leaves the user's machine. A parity test checks that it gives
exactly the same output as the Python engine.

1. On GitHub: **Settings > Pages > Build and deployment > Source: Deploy from a branch**,
   then branch `main`, folder `/docs`, and **Save**. (Pages on a private repository
   needs GitHub Pro; on a free account make the repository public first.)
2. About a minute later the site is at `https://<username>.github.io/<repo>/`.

After editing `engine/rules.py`, run `python tools/export_rules.py` to regenerate
`docs/rules.js`. Logic changes in `engine/*.py` must be mirrored in `docs/engine.js`;
`tests/test_parity.py` fails until they match (it needs Node.js).

## What it generates (8 sections)

| # | Section | How it is produced |
|---|---------|--------------------|
| 1 | Sample identity | Hashes via regex; arch/endianness/linking/stripped status from `file`/`readelf -h`; family from weighted signature scoring |
| 2 | Infection vector | 12 exploit/propagation rules (GPON `diag_Form`, Huawei HG532, Realtek UPnP, Netgear, F5, ThinkPHP, Linksys, LuCI, ViewLog.asp, Zyxel, ShellShock, Cisco, Telnet brute force), plus a **GPON relevance** verdict: direct / indirect / none |
| 3 | Static findings | File type, symbols/imports, exploit templates, CVEs, default credentials |
| 4 | Dynamic findings | Environments plus signals (no traffic, gating/anti-emulation, failed execution, reputation tags) and an explicit *observed vs inferred* verdict |
| 5 | IOC pack | IPs, URLs, domains, exploit URIs, cron entries, persistence paths, user agents, identifiers, each with a confidence level. Sandbox/lab noise (Ubuntu NTP, Canonical, Fastly, Google, Microsoft, `10.x`) is excluded and listed separately |
| 6 | ATT&CK mapping | Behaviour rules map to Enterprise IDs, or to **Mobile** IDs for Android samples; each row has an evidence source (static / dynamic / inferred) |
| 7 | Detection package | Per-sample YARA (compile-tested), generic GPON/multi-arch YARA, Suricata 6+ rules, host-hunting commands |
| 8 | Operator framework | FTTH/ISP playbook (Prevent → Detect → Contain → Eradicate → Recover), chosen by vector and behaviour, plus a priority (P1–P3) |

There is also a **Campaign view** that correlates all samples: shared C2, URLs, cron lines
and exploit sets form clusters, and an exploit-coverage matrix compares the samples.

## Bundled samples (optional)

The `samples/` folder is optional. Without it the app hides the sample list and the
Campaign view and works from pasted or uploaded analysis only; the sample-based tests
are skipped. With the five analysis reports transcribed into `samples/sampleN/`, the
engine gives these verdicts:

| Sample | Engine verdict | GPON relevance |
|--------|----------------|----------------|
| 1 | Mirai, ARM, Telnet brute-force + DDoS bot | indirect |
| 2 | Mirai (low confidence), ARM first-stage loader | indirect |
| 3 | Mozi-like multi-exploit worm, PowerPC | **direct** (`/GponForm/diag_Form`) |
| 4 | Vo1d Android TV backdoor | none (not ISP CPE) |
| 5 | Mozi-like worm, ARM counterpart of sample 3 (+ShellShock, Cisco) | **direct** |

Samples 3 and 5 cluster on `178.132.198.200/payload_v12.sh`.

## Why rules rather than ML (viva notes)

* **Explainable**: every tag traces to a regex in `engine/rules.py`, and the UI shows the evidence line and weights ("Why this family?").
* **Honest about confidence**: static-only IOCs are marked `medium`; techniques implied by a loader profile are marked `inferred`; a family supported only by a sandbox reputation tag scores `low`.
* **Extensible**: adding a new exploit means adding one dict to `VECTORS`; its Suricata rule, IOC entry, ATT&CK row and playbook actions follow automatically.

## Inputs accepted

Pasted text, or uploads: `.txt .log .md .csv .json .pdf .yar`. any.run IOC JSON exports are
flattened automatically. PDFs are read from their text layer. **Scanned PDFs** (like the
original reports) need OCR: install Tesseract plus `pytesseract` and `pillow`, or paste the
text instead. Any other file type is rejected, so binaries cannot be uploaded.

## Layout

```
app.py              Flask routes
engine/extract.py   regex IOC + ELF header extraction, noise filtering
engine/rules.py     vectors, family signatures, behaviour→ATT&CK, dynamic signals
engine/generate.py  builds the framework + cross-sample correlation
engine/detect.py    YARA / Suricata / hunting commands
engine/playbook.py  ISP operator framework
engine/render.py    Markdown export
docs/               GitHub Pages build (engine.js, rules.js generated, app.js)
tools/              export_rules.py - regenerates docs/rules.js
samples/sampleN/    static.txt, dynamic.txt, meta.json (transcribed from the reports)
tests/              regression tests
```
