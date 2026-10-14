// GPON malware framework engine - browser port of engine/*.py.
// Runs entirely client-side: analysis text never leaves the visitor's browser.
// Rule data comes from rules.js (generated from engine/rules.py).
(function (root) {
  "use strict";
  const R = typeof module !== "undefined" && module.exports ? require("./rules.js") : root.GPON_RULES;
  const VERSION = "1.0";

  // ------------------------------------------------------------ helpers
  const rx = (p, f = "i") => new RegExp(p, f);
  const search = (p, t) => rx(p).test(t);
  const lines = (t) => t.split(/\r\n|\r|\n/);
  const uniq = (arr) => {
    const seen = new Set(), out = [];
    for (const x of arr) {
      const k = typeof x === "string" ? x.toLowerCase() : x;
      if (!seen.has(k)) { seen.add(k); out.push(x); }
    }
    return out;
  };
  const sortedSet = (arr) => [...new Set(arr)].sort();
  const all = (re, t) => [...t.matchAll(re)];
  const escRe = (s) => s.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
  const fmt = (n) => n.toLocaleString("en-US");

  // ------------------------------------------------------------ extract.py
  const IPV4 = String.raw`(?<![\d.])((?:25[0-5]|2[0-4]\d|1?\d?\d)(?:\.(?:25[0-5]|2[0-4]\d|1?\d?\d)){3})(?::(\d{1,5}))?(?![\d.])`;
  const RE = {
    sha256: /\b[a-fA-F0-9]{64}\b/g,
    sha1: /(?<![a-fA-F0-9])[a-fA-F0-9]{40}(?![a-fA-F0-9])/g,
    md5: /(?<![a-fA-F0-9])[a-fA-F0-9]{32}(?![a-fA-F0-9])/g,
    ipv4: new RegExp(IPV4, "g"),
    ipv4Full: new RegExp("^" + IPV4 + "$"),
    url: /\b(?:https?|ftp|tftp):\/\/[^\s"'<>|;`)]+/gi,
    domain: /\b((?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+(?:com|net|org|ru|cn|io|info|xyz|top|biz|cc|tk|pw|su|me|in|de|uk|fr|nl|br|ir|kr|jp|tw|vn|online|site|club|live|app|dev|link))\b/gi,
    httpReq: /\b(GET|POST|PUT|HEAD)\s+(\/\S*)\s+HTTP\/1\.[01]/g,
    path: /(?<![\w.:/])(\/(?:etc|tmp|var|data|system|proc|root|dev|usr|mnt|sys|bin|sbin|home|lib)(?:\/[\w.%\-]+)*\/?)/g,
    cron: /^\s*((?:[\d*/,\-]+\s+){5}(?:wget|curl|cd|\/|sh|busybox)[^\n]*)/gm,
    ua: /(Mozilla\/5\.0 \([^)]*\)[^\n]*|User-Agent:\s*\(\)\s*\{[^\n]*)/g,
    cve: /\bCVE-\d{4}-\d{4,7}\b/gi,
    size: /file size:\s*([\d,]+)\s*bytes/i,
    entry: /entry point address:\s*(0x[0-9a-f]+)/i,
  };

  const ipInt = (ip) => ip.split(".").reduce((a, o) => a * 256 + Number(o), 0);
  const inNet = (ip, cidr) => {
    const [base, bits] = cidr.split("/");
    const size = 2 ** (32 - Number(bits));
    const start = Math.floor(ipInt(base) / size) * size;
    const v = ipInt(ip);
    return v >= start && v < start + size;
  };
  // mirrors Python ipaddress is_private / is_loopback / is_unspecified / is_reserved
  const PRIVATE_NETS = ["0.0.0.0/8", "10.0.0.0/8", "127.0.0.0/8", "169.254.0.0/16", "172.16.0.0/12",
    "192.0.0.0/29", "192.0.0.170/31", "192.0.2.0/24", "192.168.0.0/16", "198.18.0.0/15",
    "198.51.100.0/24", "203.0.113.0/24", "240.0.0.0/4", "255.255.255.255/32"];

  function classifyIp(ip) {
    if (!RE.ipv4Full.test(ip)) return ["invalid", ""];
    if (PRIVATE_NETS.some((n) => inNet(ip, n))) return ["private", "lab / private address"];
    for (const [net, note] of Object.entries(R.NOISE_NETS)) if (inNet(ip, net)) return ["noise", note];
    return ["public", ""];
  }
  const isNoiseDomain = (h) => { h = h.toLowerCase(); return R.NOISE_DOMAINS.some((d) => h === d || h.endsWith("." + d)); };

  function extract(text) {
    const sha256 = uniq(all(RE.sha256, text).map((m) => m[0].toLowerCase()));
    const buildIds = new Set(all(/BuildID\[\w+\]=([a-fA-F0-9]+)/g, text).map((m) => m[1].toLowerCase()));
    const shaJoin = sha256.join("");
    const sha1 = uniq(all(RE.sha1, text).map((m) => m[0].toLowerCase()).filter((h) => !shaJoin.includes(h) && !buildIds.has(h)));
    const md5 = uniq(all(RE.md5, text).map((m) => m[0].toLowerCase()).filter((h) => !(shaJoin + sha1.join("")).includes(h)));

    const ips = [], excluded = [], seen = new Set();
    for (const m of all(RE.ipv4, text)) {
      const ip = m[1], port = m[2] || "";
      const [kind, note] = classifyIp(ip);
      if (kind === "invalid" || seen.has(ip + "|" + port)) continue;
      seen.add(ip + "|" + port);
      if (kind === "public") ips.push({ ip, port: port ? Number(port) : null });
      else excluded.push({ value: ip + (port ? ":" + port : ""), reason: note });
    }

    const urls = [], noiseUrls = [];
    for (const m of all(RE.url, text)) {
      const u = m[0].replace(/[.,)\]}'"]+$/, "");
      const host = u.replace(/^[a-z]+:\/\//i, "").split("/")[0].split(":")[0];
      const [kind, note] = RE.ipv4Full.test(host) ? classifyIp(host) : ["public", ""];
      if (kind === "private" || kind === "noise" || isNoiseDomain(host)) noiseUrls.push({ value: u, reason: note || "sandbox / benign service" });
      else urls.push(u);
    }

    const domains = uniq(all(RE.domain, text).map((m) => m[1]).filter((d) => !isNoiseDomain(d)).map((d) => d.toLowerCase()));
    const httpRequests = uniq(all(RE.httpReq, text).map((m) => `${m[1]} ${m[2]}`));
    const paths = uniq(all(RE.path, text).map((m) => m[1].replace(/\/+$/, "") || m[1]));
    const cron = uniq(all(RE.cron, text).map((m) => m[1].trim()));
    const userAgents = uniq(all(RE.ua, text).map((m) => m[1].trim()));
    const cves = uniq(all(RE.cve, text).map((m) => m[0].toUpperCase()));
    const creds = R.KNOWN_DEFAULT_CREDS.filter((c) => new RegExp("(?<![\\w])" + escRe(c) + "(?![\\w])").test(text));
    const size = text.match(RE.size), entry = text.match(RE.entry);

    const exSeen = new Set(), ex = [];
    for (const e of excluded.concat(noiseUrls)) if (!exSeen.has(e.value)) { exSeen.add(e.value); ex.push(e); }

    return {
      sha256, sha1, md5, ips, urls: uniq(urls), domains, http_requests: httpRequests, paths, cron,
      user_agents: userAgents, cves, default_creds: creds,
      file_size: size ? Number(size[1].replace(/,/g, "")) : null,
      entry_point: entry ? entry[1] : null, excluded: ex,
    };
  }

  function parseElf(t) {
    const info = { format: null, bits: null, endian: null, arch: null, linking: null, stripped: null,
      platform: "Embedded Linux / IoT", pie: false, interpreter: null };
    const m = t.match(/ELF (32|64)-bit (LSB|MSB)/);
    if (m || /\bELF(32|64)\b/.test(t)) info.format = "ELF";
    if (m) { info.bits = Number(m[1]); info.endian = m[2] === "LSB" ? "little" : "big"; }
    else {
      const c = t.match(/Class:\s*ELF(32|64)/);
      if (c) info.bits = Number(c[1]);
      if (/little endian/i.test(t)) info.endian = "little"; else if (/big endian/i.test(t)) info.endian = "big";
    }
    const archMap = [[/\bAArch64\b/, "ARM64"], [/\bARM\b/, "ARM"], [/PowerPC/, "PowerPC"], [/\bMIPS\b/, "MIPS"],
      [/x86-64|X86-64|Advanced Micro Devices X86-64/, "x86-64"], [/Intel 80386|\bi386\b/, "x86"], [/\bSPARC\b/, "SPARC"],
      [/Motorola m?68k|\bm68k\b/, "m68k"], [/Renesas SH|SuperH/, "SuperH"], [/\bARC\b/, "ARC"]];
    const mach = t.match(/Machine:\s*([^\n]+)/);
    const hay = (mach ? mach[1] : "") + "\n" + (m ? t.slice(m.index, m.index + 120) : "");
    for (const [p, n] of archMap) if (p.test(hay)) { info.arch = n; break; }
    if (!info.arch) for (const [p, n] of archMap) if (p.test(t)) { info.arch = n; break; }
    if (/statically linked/i.test(t)) info.linking = "static"; else if (/dynamically linked/i.test(t)) info.linking = "dynamic";
    if (/not stripped/i.test(t)) info.stripped = false; else if (/\bstripped\b/i.test(t)) info.stripped = true;
    if (/\bpie executable\b|Position-Independent/i.test(t)) info.pie = true;
    const interp = t.match(/interpreter\s+(\S+?),?\s/);
    if (interp) info.interpreter = interp[1].replace(/,$/, "");
    if ((info.interpreter || "").startsWith("/system/bin/linker") || /android-tv|\/data\/local\/tmp/.test(t)) info.platform = "Android (TV box / set-top)";
    return info;
  }

  // ------------------------------------------------------------ generate.py
  const NOTABLE_STRINGS = [
    [String.raw`\bklv123\b`, "Mozi-style node identifier"],
    [String.raw`\bLotus\b`, "Possible campaign/build identifier"],
    [String.raw`android-tv-[a-z]+`, "Vo1d stage identifier"],
    [String.raw`\.kworker\b`, "Masquerade file name (fake kernel worker)"],
    [String.raw`\bS99bot\b`, "Init-script persistence name"],
    [String.raw`\bbot\.service\b`, "systemd persistence unit"],
    [String.raw`[\w\-]+bins?\.sh\b|payload_v\d+\.sh`, "Second-stage shell script name"],
  ];
  const PERSIST_PATH = /^\/(etc\/(rc\.local|init\.d|systemd|cron|crontabs|config|profile\.d)|var\/spool\/cron|root\/\.|tmp\/\.|tmp\/bot|data\/local\/tmp|system\/?$)/;
  const ORDER = ["Initial Access", "Execution", "Persistence", "Defense Evasion", "Discovery", "Lateral Movement", "Command and Control", "Impact"];

  function linesMatching(text, pattern, limit = 3) {
    const re = rx(pattern), out = [];
    for (const line of lines(text)) {
      if (re.test(line)) {
        const s = line.trim();
        out.push(s.length <= 180 ? s : s.slice(0, 177) + "...");
        if (out.length >= limit) break;
      }
    }
    return out;
  }
  function source(p, s, d) {
    const a = search(p, s), b = search(p, d);
    return a && b ? "static + dynamic" : a ? "static" : b ? "dynamic" : null;
  }

  function matchVectors(st, dy) {
    const found = [];
    for (const v of R.VECTORS) {
      const p = v.patterns.join("|"), src = source(p, st, dy);
      if (!src) continue;
      found.push({ id: v.id, name: v.name, target: v.target, cves: v.cves, note: v.note || null,
        gpon: !!v.gpon, telnet: !!v.telnet, source: src, evidence: linesMatching(st + "\n" + dy, p, 2) });
    }
    return found;
  }

  function scoreFamilies(text, exploitCount) {
    const t = text + (exploitCount >= 5 ? "\n__MULTI_EXPLOIT__" : "");
    const scores = [];
    for (const [fam, sigs] of Object.entries(R.FAMILIES)) {
      let total = 0; const why = [];
      for (const [p, w, label] of sigs) if (search(p, t)) { total += w; why.push({ signal: label, weight: w }); }
      if (total) scores.push({ family: fam, score: total, evidence: why });
    }
    return scores.sort((a, b) => b.score - a.score); // stable, like Python's sort
  }

  function familyVerdict(scores) {
    if (!scores.length) return ["Unknown", "low", "No family signatures matched."];
    const top = scores[0], second = scores.length > 1 ? scores[1].score : 0;
    let conf = top.score >= 6 ? "high" : top.score >= 3 ? "moderate" : "low";
    let note = `Top score ${top.score} vs next ${second}.`;
    if (top.score - second < 2 && second) { conf = conf === "moderate" ? "low" : "moderate"; note += " Close runner-up - treat as ambiguous."; }
    if (top.family === "Mirai" && top.score <= 1) note += " Only a sandbox reputation tag supports this; such tags are applied broadly to IoT bots.";
    return [top.family, conf, note];
  }

  function behaviours(st, dy, ctx) {
    const hits = [];
    for (const b of R.BEHAVIOURS) {
      let src = null, evidence = [];
      const d = b.derived;
      if (d === "vectors_exploit") {
        if (ctx.exploit_vectors.length) {
          src = "static";
          evidence = [`${ctx.exploit_vectors.length} exploit template(s): ` + ctx.exploit_vectors.slice(0, 6).map((v) => v.name.split(" ")[0]).join(", ")];
        }
      } else if (d === "nonstd_port") {
        const ports = ctx.iocs.ips.filter((i) => i.port && ![80, 443, 8080].includes(i.port)).map((i) => `${i.ip}:${i.port}`);
        if (ports.length) { src = "static"; evidence = ports; }
      } else if (d === "worm") {
        if (ctx.exploit_vectors.length || ctx.telnet) { src = "static"; evidence = ["Embedded scanner/exploit logic targets other devices"]; }
      } else if (d === "resource_hijack") {
        if (ctx.roles.length && ctx.roles.join(" ").includes("Worm") && !ctx.ddos) { src = "inferred"; evidence = ["Botnet enrolment; payload function unknown (low confidence)"]; }
      } else {
        const p = b.patterns.join("|");
        src = source(p, st, dy);
        if (src) evidence = linesMatching(st + "\n" + dy, p, 2);
      }
      if (!src) continue;
      let technique = b.technique, tid = b.tid;
      if (ctx.android && b.mobile) [technique, tid] = b.mobile;
      hits.push({ id: b.id, behaviour: b.name, tactic: b.tactic, technique, tid, source: src, evidence });
    }
    const ids = new Set(hits.map((h) => h.id));
    if (ctx.roles.some((r) => r.includes("loader")) && ctx.iocs.ips.length) {
      if (!ids.has("http_c2")) hits.push({ id: "http_c2", behaviour: "C2 contact (hypothesised)", tactic: "Command and Control",
        technique: "Application Layer Protocol (hypothesised)", tid: "T1071", source: "inferred",
        evidence: ["Embedded IP " + ctx.iocs.ips[0].ip + "; no traffic observed"] });
      if (!ids.has("ingress")) hits.push({ id: "ingress", behaviour: "Second-stage retrieval (hypothesised)",
        tactic: "Command and Control", technique: "Ingress Tool Transfer (hypothesised)", tid: "T1105", source: "inferred",
        evidence: ["Small stripped binary + CPU fingerprinting = loader profile"] });
    }
    const rank = (h) => (ORDER.includes(h.tactic) ? ORDER.indexOf(h.tactic) : 99);
    return hits.sort((a, b) => rank(a) - rank(b));
  }

  function roles(elf, iocs, vectors, beh) {
    const out = [];
    if (vectors.filter((v) => !v.telnet).length >= 2) out.push("Multi-exploit worm");
    if (vectors.some((v) => v.telnet)) out.push("Telnet brute-force bot");
    if (beh.has("ddos")) out.push("DDoS bot");
    if (beh.has("backdoor_listener") || (elf.platform.startsWith("Android") && beh.has("shell_exec"))) out.push("Backdoor");
    const small = iocs.file_size && iocs.file_size < 60000;
    if (small && elf.stripped && beh.has("sysinfo") && !["cron", "initd", "systemd"].some((x) => beh.has(x))) out.push("First-stage loader / dropper");
    if (!out.length) out.push("Unclassified payload");
    return out;
  }

  function dynamicSummary(dy) {
    const signals = [];
    for (const [id, p, label] of R.DYNAMIC_SIGNALS) if (search(p, dy)) signals.push({ id, label, evidence: linesMatching(dy, p, 1) });
    const envs = [], ls = lines(dy);
    ls.forEach((line, n) => {
      const m = line.match(/^\s*((?:Local|Cloud)[^:]{0,80}):\s*(.*)/);
      if (!m) return;
      let note = m[2].trim();
      if (!note) {
        let block = ls.slice(n + 1, n + 10).map((l) => l.trim()).filter(Boolean);
        const stop = block.findIndex((l) => /^(Local|Cloud)/.test(l));
        if (stop >= 0) block = block.slice(0, stop);
        note = block.find((l) => l.startsWith("Result:")) ||
          (block.find((l) => l.startsWith("-")) || "").slice(1).trim() ||
          block.find((l) => !/^(\$|sudo|timeout)/.test(l)) || "";
      }
      envs.push({ environment: m[1].trim(), note });
    });
    const ids = new Set(signals.map((s) => s.id));
    let verdict, level;
    if (!dy.trim()) { verdict = "No dynamic analysis supplied - all findings are static/inferred."; level = "none"; }
    else if (ids.has("no_traffic") && ids.has("gating")) {
      verdict = "Sample ran but produced no malicious network traffic; behaviour is most likely gated (reachability/anti-emulation). Network IOCs remain static-derived."; level = "partial";
    } else if (ids.has("no_traffic") || ids.has("failed_exec")) { verdict = "Dynamic runs did not confirm network behaviour; treat C2/payload IOCs as unconfirmed."; level = "partial"; }
    else if (ids.has("instability")) { verdict = "Execution was too aggressive to observe cleanly - itself a behavioural indicator."; level = "partial"; }
    else { verdict = "Dynamic observations available."; level = "observed"; }
    return { signals, environments: envs, verdict, level };
  }

  function buildIocs(st, dy, iocs, vectors, meta) {
    const out = [], full = st + "\n" + dy, fl = lines(full);
    const add = (type, value, context, confidence, src = "static") => {
      if (!out.some((o) => o.type === type && o.value === value)) out.push({ type, value, context, confidence, source: src });
    };
    for (const h of iocs.sha256) {
      const line = fl.find((l) => l.toLowerCase().includes(h)) || "";
      if (/archive|\.zip/i.test(line)) add("SHA256 (archive)", h, "Distribution archive", "high");
      else add("SHA256 (sample)", h, "Analysed ELF sample", "high");
    }
    for (const h of iocs.md5) add("MD5", h, "Hash from analysis notes", "high");
    for (const ip of iocs.ips) {
      const val = ip.ip + (ip.port ? ":" + ip.port : "");
      const inUrl = iocs.urls.some((u) => u.includes(ip.ip));
      const ctx = ip.port ? "C2 endpoint (IP:port in binary)" : inUrl ? "Payload host" : "IP string in binary";
      const neg = dy.includes(ip.ip);
      const dynLines = lines(dy).filter((l) => l.includes(ip.ip));
      const observed = dynLines.some((l) => !/\bno\b|none|not|0 packets|grep/i.test(l));
      if (observed) add("IP", val, ctx + " - observed in dynamic run", "high", "static + dynamic");
      else add("IP", val, ctx + (neg ? " - not observed in dynamic runs" : ""), "medium", "static");
    }
    if (meta.c2) add("IP/Domain (analyst)", meta.c2.trim(), "C2 supplied by analyst", "medium", "analyst");
    for (const u of iocs.urls) add("URL", u, "Second-stage payload URL", "medium");
    for (const d of iocs.domains) add("Domain", d, "Domain string in analysis", "medium");
    for (const v of vectors) {
      if (v.telnet) continue;
      const rv = R.VECTORS.find((r) => r.id === v.id);
      if (rv.uri) add("Exploit URI", rv.uri, v.name + (v.cves.length ? ` (${v.cves.join(", ")})` : ""), "high");
    }
    for (const c of iocs.cron) add("Cron entry", c, "Persistence / auto re-infection", "high");
    for (const p of iocs.paths) if (PERSIST_PATH.test(p)) add("File path", p, "Persistence or staging location", "high");
    for (const ua of iocs.user_agents) {
      if (ua.toLowerCase().startsWith("user-agent")) add("User-Agent", ua, "ShellShock exploit header", "high");
      else add("User-Agent", ua, "Hard-coded UA (HTTP flood / scanning)", "low");
    }
    for (const [p, label] of NOTABLE_STRINGS) for (const m of sortedSet(all(new RegExp(p, "g"), st).map((x) => x[0]))) add("String", m, label, "medium");
    if (iocs.default_creds.length) add("Credential list", iocs.default_creds.join(", "), "Default credentials used for brute force", "high");
    return out;
  }

  function risk(vectors, beh, iocsList, fconf, rl) {
    const factors = [];
    const f = (name, pts) => { if (pts) factors.push({ factor: name, points: pts }); };
    const exploit = vectors.filter((v) => !v.telnet);
    f(`${exploit.length} remote-exploit vector(s)`, Math.min(30, 4 * exploit.length));
    f("GPON ONT exploit present", vectors.some((v) => v.gpon) ? 10 : 0);
    f("Telnet brute-force propagation", vectors.some((v) => v.telnet) ? 15 : 0);
    f("Self-propagating (worm)", beh.has("worm") ? 10 : 0);
    const persist = ["cron", "initd", "systemd", "shell_profile", "openwrt_cfg", "boot_android"].filter((x) => beh.has(x)).length;
    f(`${persist} persistence mechanism(s)`, Math.min(15, 5 * persist));
    f("DDoS capability", beh.has("ddos") ? 15 : 0);
    const evasion = ["anti_emu", "obfuscation", "masquerade", "fileless", "cleanup"].filter((x) => beh.has(x)).length;
    f(`${evasion} evasion technique(s)`, Math.min(10, 3 * evasion));
    f("Remote backdoor / command execution", rl.includes("Backdoor") ? 15 : 0);
    f("Loader stage (enables later payloads)", rl.some((r) => r.includes("loader")) ? 10 : 0);
    f("Network C2/payload IOC known", iocsList.some((i) => i.type === "IP" || i.type === "URL") ? 5 : 0);
    const score = Math.min(100, factors.reduce((a, x) => a + x.points, 0));
    const level = score >= 70 ? "Critical" : score >= 50 ? "High" : score >= 30 ? "Medium" : "Low";
    return { score, level, factors, note: `Family confidence: ${fconf}. Score reflects capability, not observed impact.` };
  }

  function generatedAt() {
    const d = new Date(), p = (n) => String(n).padStart(2, "0");
    return `${d.getUTCFullYear()}-${p(d.getUTCMonth() + 1)}-${p(d.getUTCDate())} ${p(d.getUTCHours())}:${p(d.getUTCMinutes())} UTC`;
  }

  function generate(staticText = "", dynamicText = "", metaIn = {}) {
    const meta = {};
    for (const [k, v] of Object.entries(metaIn || {})) meta[k] = typeof v === "string" ? v.trim() : v;
    let st = staticText || "";
    const dy = dynamicText || "";
    if (meta.exploit_url) st += "\n" + meta.exploit_url;
    const full = st + "\n" + dy;

    const iocs = extract(full);
    const elf = parseElf(st);
    if (meta.arch) elf.arch_analyst = meta.arch;
    const vectors = matchVectors(st, dy);
    const exploitVectors = vectors.filter((v) => !v.telnet);
    const android = elf.platform.startsWith("Android");
    const scores = scoreFamilies(full, exploitVectors.length);
    const [family, fconf, fnote] = familyVerdict(scores);

    const ctx = { exploit_vectors: exploitVectors, telnet: vectors.some((v) => v.telnet), iocs, android, roles: [], ddos: false };
    let beh = behaviours(st, dy, ctx);
    let behIds = new Set(beh.map((b) => b.id));
    const rl = roles(elf, iocs, vectors, behIds);
    ctx.roles = rl; ctx.ddos = behIds.has("ddos");
    beh = behaviours(st, dy, ctx); // second pass for role-dependent rules
    behIds = new Set(beh.map((b) => b.id));

    const fl = lines(full);
    const sampleSha = meta.sha256 || iocs.sha256.find((h) => !/archive|\.zip/i.test(fl.find((l) => l.toLowerCase().includes(h)) || ""))
      || iocs.sha256[0] || null;

    let relevance;
    if (vectors.some((v) => v.gpon)) relevance = ["direct", "Carries the GPON diag_Form exploit - can compromise vulnerable ONTs directly."];
    else if (android) relevance = ["none", "Targets Android TV boxes, not ISP CPE. Relevant only as a subscriber-side threat behind the ONT."];
    else if (vectors.some((v) => !v.gpon)) relevance = ["indirect", "No GPON exploit, but targets the same embedded/router class - ONTs with Telnet or web management exposed are at risk."];
    else relevance = ["indirect", "No infection vector recovered (loader stage) - may deliver GPON-capable payloads."];

    const iocsList = buildIocs(st, dy, iocs, vectors, meta);
    const dyn = dynamicSummary(dy);
    const rsk = risk(vectors, behIds, iocsList, fconf, rl);

    const symbols = sortedSet(all(/\b(telnet_scanner|getRandomIP|killer_loop|start_killer|spoof_process_name|install_persistence|initConnection|processCmd|l4resattack|vseattack|r6attack|SendUDP|SendHTTPHex|SendSTDHEX|sendHTTPtwo|socket|bind|listen|accept|connect|fork|setsid|prctl|execl|system|dlopen|uname)\b/g, st).map((m) => m[1]));
    const fileLine = (lines(st).find((l) => /\bELF (32|64)-bit/.test(l)) || "").trim() || null;
    const cveAll = sortedSet(iocs.cves.concat(vectors.flatMap((v) => v.cves)));

    const findings = [
      fileLine && { label: "File type", value: fileLine },
      { label: "Architecture", value: [elf.arch, elf.bits && `${elf.bits}-bit`, elf.endian && `${elf.endian}-endian`].filter(Boolean).join(" / ") },
      { label: "Linking", value: (elf.linking || "unknown") + (elf.pie ? " (PIE)" : "") },
      { label: "Symbols", value: elf.stripped === true ? "stripped" : elf.stripped === false ? "present (not stripped)" : "unknown" },
      elf.interpreter && { label: "Interpreter", value: elf.interpreter },
      iocs.entry_point && { label: "Entry point", value: iocs.entry_point },
      iocs.file_size && { label: "File size", value: `${fmt(iocs.file_size)} bytes` },
      { label: "Packer", value: /\bUPX!?\b/.test(st) ? "UPX detected" : "none detected in notes" },
      symbols.length && { label: "Capability symbols/imports", value: symbols.join(", ") },
      iocs.http_requests.length && { label: "Exploit request templates", value: String(iocs.http_requests.length) },
      cveAll.length && { label: "CVE references", value: cveAll.join(", ") },
      iocs.default_creds.length && { label: "Default credentials", value: `${iocs.default_creds.length} known defaults matched` },
    ].filter((f) => f && f.value);

    const fw = {
      meta: { generator: "GPON Malware Framework Generator", version: VERSION, generated_at: generatedAt(), source_report: meta.source_report || null },
      identity: {
        name: meta.name || (sampleSha ? `Sample ${sampleSha.slice(0, 12)}` : "Unnamed sample"),
        sha256: sampleSha, hashes: { sha256: iocs.sha256, sha1: iocs.sha1, md5: iocs.md5 },
        platform: elf.platform, arch: elf.arch_analyst || elf.arch, bits: elf.bits, endian: elf.endian,
        linking: elf.linking, stripped: elf.stripped, file_size: iocs.file_size,
        family, family_confidence: fconf, family_note: fnote, family_scores: scores,
        family_analyst: meta.family || null, roles: rl,
      },
      vector: { gpon_relevance: relevance[0], gpon_summary: relevance[1], vectors },
      static: { findings, http_requests: iocs.http_requests },
      dynamic: dyn, iocs: iocsList, excluded: iocs.excluded, attack: beh, risk: rsk,
    };
    fw.detections = buildDetections(fw);
    fw.operator = buildPlaybook(fw);
    return fw;
  }

  // ------------------------------------------------------------ detect.py
  const CRC_TABLE = (() => { const t = []; for (let n = 0; n < 256; n++) { let c = n; for (let k = 0; k < 8; k++) c = c & 1 ? 0xedb88320 ^ (c >>> 1) : c >>> 1; t[n] = c >>> 0; } return t; })();
  const crc32 = (s) => { let c = 0xffffffff; for (const b of new TextEncoder().encode(s)) c = CRC_TABLE[(c ^ b) & 0xff] ^ (c >>> 8); return (c ^ 0xffffffff) >>> 0; };
  const yEsc = (s) => s.replace(/\\/g, "\\\\").replace(/"/g, '\\"');

  function ruleName(fw) {
    const fam = (fw.identity.family || "Unknown").replace(/[^A-Za-z0-9]/g, "") || "Unknown";
    return `GPONFW_${fam}_${(fw.identity.sha256 || "nohash").slice(0, 8)}`;
  }

  function buildYara(fw) {
    const strings = [];
    for (const { type: t, value: v } of fw.iocs) {
      if (t === "IP") { strings.push(["ip", v.split(":")[0]]); if (v.includes(":")) strings.push(["c2", v]); }
      else if (t === "URL" || t === "Domain") strings.push(["net", v]);
      else if (t === "Exploit URI") strings.push(["exp", v.includes("invokefunction") ? "invokefunction" : v.split("?")[0]]);
      else if (t === "String") strings.push(["id", v]);
      else if (t === "Cron entry") strings.push(["cron", v.slice(0, 60).trim()]);
      else if (t === "User-Agent" && v.toLowerCase().startsWith("user-agent")) strings.push(["ua", "() { :; };"]);
    }
    const symText = fw.static.findings.map((f) => f.value).join(" ");
    for (const m of all(/\b(telnet_scanner|killer_loop|install_persistence|spoof_process_name|l4resattack)\b/g, symText)) strings.push(["sym", m[1]]);
    const seen = new Set(), u = [];
    for (const [k, v] of strings) if (!seen.has(v) && v.length >= 4) { seen.add(v); u.push([k, v]); }
    const uq = u.slice(0, 24);
    if (!uq.length) return "// Not enough static strings recovered to build a meaningful YARA rule for this sample.";
    const counters = {}, body = uq.map(([k, v]) => { counters[k] = (counters[k] || 0) + 1; return `        $${k}${counters[k]} = "${yEsc(v)}" ascii`; }).join("\n");
    const n = uq.length, need = n <= 2 ? n : Math.max(2, Math.floor(n / 3)), i = fw.identity;
    return `rule ${ruleName(fw)}
{
    meta:
        description = "${yEsc(i.family)} (${i.roles.join(", ")}) - generated from analysis notes"
        author = "GPON Malware Framework Generator"
        date = "${fw.meta.generated_at.slice(0, 10)}"
        sha256 = "${i.sha256 || "n/a"}"
        arch = "${i.arch || "unknown"}"
        confidence = "${i.family_confidence}"
    strings:
${body}
    condition:
        uint32(0) == 0x464c457f and filesize < 8MB and ${need === n ? "all of them" : `${need} of them`}
}`;
  }

  const GENERIC_YARA = String.raw`rule GPONFW_Generic_GPON_Exploit_Template
{
    meta:
        description = "ELF carrying a GPON diag_Form exploit template (CVE-2018-10561/10562)"
        author = "GPON Malware Framework Generator"
    strings:
        $uri = "/GponForm/diag_Form" ascii nocase
        $img = "images/" ascii
        $inj1 = "XWebPageName=diag" ascii
        $inj2 = "dest_host=" ascii
        $dl1 = "wget" ascii
        $dl2 = "curl" ascii
    condition:
        uint32(0) == 0x464c457f and $uri and ($img or any of ($inj*)) and any of ($dl*)
}

rule GPONFW_Generic_MultiArch_Downloader
{
    meta:
        description = "ELF/script that fetches per-architecture bot binaries"
        author = "GPON Malware Framework Generator"
    strings:
        $a1 = ".arm7" ascii
        $a2 = ".mips" ascii
        $a3 = ".mpsl" ascii
        $a4 = ".x86" ascii
        $a5 = ".ppc" ascii
        $a6 = ".arm5" ascii
        $w1 = "wget " ascii
        $w2 = "tftp " ascii
        $w3 = "busybox" ascii
    condition:
        filesize < 2MB and 3 of ($a*) and any of ($w*)
}`;

  function buildSuricata(fw) {
    let sid = 9100000 + (crc32(fw.identity.sha256 || fw.identity.name) % 8900) * 100;
    const out = [], rule = (t) => { sid += 1; out.push(t.replace("__SID__", String(sid))); };
    for (const v of fw.vector.vectors) {
      const rv = R.VECTORS.find((r) => r.id === v.id);
      const refs = v.cves.map((c) => ` reference:cve,${c.slice(4)};`).join("");
      if (rv.suricata_uri) {
        const contents = rv.suricata_uri.map((c) => `content:"${yEsc(c)}"; nocase;`).join(" ");
        rule(`alert http any any -> any any (msg:"GPONFW Exploit attempt - ${v.name}"; flow:established,to_server; http.uri; ${contents}${refs} classtype:attempted-admin; sid:__SID__; rev:1;)`);
      }
      if (rv.header) rule(`alert http any any -> any any (msg:"GPONFW Exploit attempt - ${v.name}"; flow:established,to_server; http.user_agent; content:"() {"; ${refs} classtype:attempted-admin; sid:__SID__; rev:1;)`);
      if (rv.suricata_body) rule(`alert http any any -> any any (msg:"GPONFW Exploit attempt - ${v.name}"; flow:established,to_server; http.request_body; content:"${yEsc(rv.suricata_body)}";${refs} classtype:attempted-admin; sid:__SID__; rev:1;)`);
      if (rv.telnet) rule('alert tcp $HOME_NET any -> $EXTERNAL_NET [23,2323] (msg:"GPONFW Outbound Telnet scanning from subscriber device"; flags:S,12; threshold:type both, track by_src, count 30, seconds 60; classtype:network-scan; sid:__SID__; rev:1;)');
    }
    for (const i of fw.iocs) {
      if (i.type === "IP") {
        const [ip, port] = i.value.split(":");
        if (port) rule(`alert tcp $HOME_NET any -> ${ip} ${port} (msg:"GPONFW Connection to C2 ${i.value}"; flow:to_server; classtype:trojan-activity; sid:__SID__; rev:1;)`);
        else rule(`alert ip $HOME_NET any -> ${ip} any (msg:"GPONFW Traffic to malware host ${ip}"; classtype:trojan-activity; sid:__SID__; rev:1;)`);
      } else if (i.type === "URL") {
        const m = i.value.match(/^\w+:\/\/([^/:]+)(?::\d+)?(\/[^?#]*)?/);
        if (m && m[2]) rule(`alert http $HOME_NET any -> any any (msg:"GPONFW Payload download ${yEsc(m[2])}"; flow:established,to_server; http.host; content:"${yEsc(m[1])}"; http.uri; content:"${yEsc(m[2])}"; classtype:trojan-activity; sid:__SID__; rev:1;)`);
      } else if (i.type === "Domain") {
        rule(`alert dns $HOME_NET any -> any any (msg:"GPONFW DNS lookup of ${i.value}"; dns.query; content:"${yEsc(i.value)}"; nocase; classtype:trojan-activity; sid:__SID__; rev:1;)`);
      }
    }
    const ids = new Set(fw.attack.map((b) => b.id));
    if (ids.has("ingress") || ids.has("fileless")) {
      rule('alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"GPONFW Embedded device fetching multi-arch bot binary"; flow:established,to_server; http.uri; pcre:"/\\.(arm[4-7]?|mips|mpsl|x86|x86_64|ppc|m68k|sh4|spc|arc)$/i"; classtype:trojan-activity; sid:__SID__; rev:1;)');
      rule('alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"GPONFW ELF binary delivered over HTTP"; flow:established,to_client; file.data; content:"|7F 45 4C 46|"; startswith; classtype:trojan-activity; sid:__SID__; rev:1;)');
    }
    return out;
  }

  function buildHunt(fw) {
    const cmds = [], android = fw.identity.platform.startsWith("Android");
    const paths = fw.iocs.filter((i) => i.type === "File path").map((i) => i.value);
    const ips = fw.iocs.filter((i) => i.type === "IP").map((i) => i.value.split(":")[0]);
    if (android) {
      cmds.push("adb shell ls -la /data/local/tmp/",
        "adb shell ps -A | grep -v -E '^(root|system|shell) .*(zygote|servicemanager)'",
        "adb shell getprop | grep -i -E 'sysboot|preboot'",
        "adb shell ls -la /proc/*/exe 2>/dev/null | grep -E 'data/local/tmp|deleted'");
    } else {
      if (paths.length) cmds.push("ls -la " + sortedSet(paths).join(" ") + " 2>/dev/null");
      cmds.push("cat /var/spool/cron/crontabs/root /etc/crontabs/root /etc/cron.d/* 2>/dev/null | grep -E 'wget|curl|\\| *sh'",
        "ls -la /proc/*/exe 2>/dev/null | grep -E '(deleted)|/tmp/|/var/run/|/dev/shm/'",
        "ps w | grep -E 'kworker|\\.s$|/tmp/' | grep -v grep",
        "netstat -antp 2>/dev/null | grep -E ':23 |:2323 |ESTABLISHED'");
    }
    for (const ip of ips) cmds.push(`netstat -an 2>/dev/null | grep ${ip}`);
    return cmds;
  }

  function buildDetections(fw) {
    let yara = buildYara(fw);
    if (fw.vector.gpon_relevance === "direct" || fw.attack.some((b) => b.id === "ingress")) yara += "\n\n" + GENERIC_YARA;
    return { yara, suricata: buildSuricata(fw), hunt: buildHunt(fw) };
  }

  // ------------------------------------------------------------ playbook.py
  function buildPlaybook(fw) {
    const vectors = fw.vector.vectors, beh = new Set(fw.attack.map((b) => b.id));
    const rel = fw.vector.gpon_relevance, android = fw.identity.platform.startsWith("Android");
    const gpon = vectors.some((v) => v.gpon), telnet = vectors.some((v) => v.telnet);
    const other = vectors.filter((v) => !v.gpon && !v.telnet);
    const ips = fw.iocs.filter((i) => i.type === "IP").map((i) => i.value);
    const urls = fw.iocs.filter((i) => i.type === "URL").map((i) => i.value);
    const persistPaths = fw.iocs.filter((i) => i.type === "File path" || i.type === "Cron entry").map((i) => i.value);
    const prevent = [], detect = [], contain = [], eradicate = [];

    if (gpon) prevent.push(
      "Push patched ONT firmware fixing CVE-2018-10561/10562 (auth bypass + diag_Form injection) via OMCI or the TR-069 ACS.",
      "Disable WAN-side web management on all ONTs (TCP 80/8080/443/8443); allow it only from the ISP management VLAN.",
      "Add an edge/BNG ACL dropping Internet-sourced HTTP to subscriber ONT management addresses.",
      "Add an IPS/WAF rule at the edge rejecting any request whose URI contains /GponForm/ or 'images/' after a form path.");
    if (telnet) prevent.push(
      "Disable Telnet (TCP 23/2323) on all CPE/ONTs through TR-069 and block inbound 23/2323 at the edge.",
      "Provision unique per-device admin passwords; the sample's wordlist targets factory defaults.");
    if (other.length) {
      prevent.push("Audit the CPE/managed-device inventory for these targeted platforms and patch or replace: " + sortedSet(other.map((v) => v.target)).join("; ") + ".");
      prevent.push("Close TR-064/UPnP (TCP 7547, 37215, 52869) on the WAN side of ISP-supplied CPE.");
    }
    if (android) prevent.push(
      "This is not ISP CPE: publish subscriber guidance to avoid uncertified Android TV boxes and update firmware.",
      "Offer DNS-based protection (RPZ) for residential subscribers once Vo1d C2 domains are obtained from decrypted config/threat intel.");
    if (!vectors.length && !android) prevent.push("Loader only: harden against the likely delivery paths (Telnet, GPON diag_Form, router web RCE) as a precaution.");

    detect.push("Deploy the generated Suricata rules on the BNG/aggregation mirror port and the YARA rules on firmware/binary collection points.");
    if (telnet || gpon || other.length) detect.push("NetFlow/IPFIX: alert on subscriber IPs with high fan-out to TCP 23/2323/80/8080/7547 (worm scanning).");
    if (gpon) detect.push("Monitor OLT/ONT alarms for unexpected reboots, CPU spikes or config changes on ONT models known to be vulnerable.");
    if (ips.length || urls.length) detect.push("Alert on any subscriber traffic to: " + ips.concat(urls).join(", ") + ".");
    if (beh.has("ddos")) detect.push("Watch for outbound UDP/HTTP flood patterns from single subscribers (sudden upstream saturation).");
    if (beh.has("anti_emu") || fw.dynamic.level !== "observed") detect.push("Network IOCs were not confirmed dynamically - prioritise behaviour-based rules (scanning, ELF downloads) over IP blocklists alone.");

    contain.push(android
      ? "Notify the affected subscriber; rate-limit or walled-garden the subscriber line if the device is attacking others."
      : "Move affected subscriber ONTs/CPE to a walled-garden/quarantine VLAN; keep management access for remediation.");
    if (ips.length) contain.push("Null-route / firewall the C2 and payload hosts at the edge: " + ips.map((i) => i.split(":")[0]).join(", ") + ".");
    if (urls.length) contain.push("Block the payload URL(s) at the transparent proxy / DNS layer so re-infection fetches fail.");
    if (telnet || gpon || other.length) contain.push("Rate-limit or block outbound scanning (23/2323/80/8080) from the quarantined lines to stop worm propagation.");

    const persist = ["cron", "initd", "systemd", "shell_profile", "openwrt_cfg", "boot_android"].filter((x) => beh.has(x)).sort();
    if (persist.length) {
      eradicate.push("A reboot alone is NOT sufficient - the sample installs persistence (" + persist.join(", ") + "). Factory-reset and reflash firmware.");
      if (persistPaths.length) eradicate.push("Verify removal of: " + persistPaths.slice(0, 8).join("; ") + ".");
    } else {
      eradicate.push("Reboot clears memory-resident IoT bots, but reflash firmware anyway and patch before reconnecting, otherwise re-infection occurs within minutes.");
    }
    eradicate.push("Rotate all device credentials (admin, Telnet/SSH, Wi-Fi) after reflash.");
    if (android) eradicate.push("Android TV box: full firmware reflash from the vendor, or replace the device if unsupported.");

    const recover = [
      "Restore service only after the device reports patched firmware and passes a WAN-side port check.",
      "Keep the line under enhanced monitoring for 14 days (re-infection indicators above).",
      "Share IOCs with the national CERT / MISP community and record the incident against the CPE model.",
    ];
    const priority = rel === "direct" ? "P1 - active GPON ONT exploitation capability"
      : ["Critical", "High"].includes(fw.risk.level) ? "P2 - high-capability IoT threat to subscriber equipment"
      : android ? "P3 - subscriber-side device threat (not ISP CPE)" : "P3 - monitor and harden";
    return { priority, phases: [
      { phase: "Prevent / harden", actions: prevent }, { phase: "Detect", actions: detect },
      { phase: "Contain", actions: contain }, { phase: "Eradicate", actions: eradicate },
      { phase: "Recover & report", actions: recover }] };
  }

  // ------------------------------------------------------------ render.py
  function toMarkdown(fw) {
    const e = (s) => String(s ?? "").replace(/\|/g, "\\|").replace(/\n/g, " ");
    const table = (h, rows) => ["| " + h.join(" | ") + " |", "|" + "---|".repeat(h.length), ...rows.map((r) => "| " + r.map(e).join(" | ") + " |")].join("\n");
    const i = fw.identity, v = fw.vector, d = fw.dynamic, r = fw.risk;
    const md = [`# GPON Malware Framework - ${i.name}`, "",
      `_Generated ${fw.meta.generated_at} by ${fw.meta.generator} v${fw.meta.version}_`, "",
      `**Risk:** ${r.level} (${r.score}/100) · **Priority:** ${fw.operator.priority} · **GPON relevance:** ${v.gpon_relevance}`, "",
      "## 1. Sample identity", "", table(["Field", "Value"], [
        ["SHA256", i.sha256 || "-"], ["Platform", i.platform],
        ["Architecture", [i.arch, i.bits && `${i.bits}-bit`, i.endian && `${i.endian}-endian`].filter(Boolean).join(" ") || "unknown"],
        ["Linking / symbols", `${i.linking || "unknown"} / ${i.stripped ? "stripped" : i.stripped === false ? "not stripped" : "?"}`],
        ["File size", i.file_size ? `${fmt(i.file_size)} bytes` : "-"], ["Family (engine)", `${i.family} - ${i.family_confidence} confidence`],
        ["Family (analyst)", i.family_analyst || "-"], ["Role", i.roles.join(", ")]]), "", `_${i.family_note}_`, "",
      "## 2. Infection vector", "", v.gpon_summary, "",
      v.vectors.length ? table(["Vector", "Target", "CVE", "Source"], v.vectors.map((x) => [x.name, x.target, x.cves.join(", ") || "-", x.source])) : "No infection vector recovered from the analysis.", "",
      "## 3. Static findings", "", table(["Finding", "Value"], fw.static.findings.map((f) => [f.label, f.value])), "",
      "## 4. Dynamic findings", "", `**Assessment:** ${d.verdict}`, "",
      ...d.environments.map((x) => `- **${x.environment}**: ${x.note}`), ...d.signals.map((s) => `- ${s.label}`), "",
      "## 5. IOC pack", "", table(["Type", "Indicator", "Context", "Confidence"], fw.iocs.map((x) => [x.type, x.value, x.context, x.confidence])), ""];
    if (fw.excluded.length) md.push("Excluded as sandbox/lab noise: " + fw.excluded.map((x) => "`" + x.value + "`").join(", "), "");
    md.push("## 6. ATT&CK mapping", "", table(["Tactic", "Technique", "ID", "Evidence"], fw.attack.map((a) => [a.tactic, a.technique, a.tid, a.source])), "",
      "## 7. Detection package", "", "### YARA", "```yara", fw.detections.yara, "```", "",
      "### Suricata", "```", ...fw.detections.suricata, "```", "", "### Host hunting", "```sh", ...fw.detections.hunt, "```", "",
      "## 8. Operator framework (FTTH / ISP)", "", `**Priority:** ${fw.operator.priority}`, "");
    for (const p of fw.operator.phases) md.push(`### ${p.phase}`, ...p.actions.map((a) => `- ${a}`), "");
    md.push("## Risk score breakdown", "", table(["Factor", "Points"], r.factors.map((f) => [f.factor, f.points])), "", `_${r.note}_`, "");
    return md.join("\n");
  }

  // ------------------------------------------------------------ ingest.py (JSON part; PDF is handled in app.js)
  function flattenJson(obj, prefix = "") {
    if (Array.isArray(obj)) return obj.flatMap((v) => flattenJson(v, prefix));
    if (obj && typeof obj === "object") {
      if (typeof obj.ioc === "string") return [`${obj.category ?? prefix} ${obj.type ?? ""}: ${obj.ioc}`];
      return Object.entries(obj).flatMap(([k, v]) => flattenJson(v, k));
    }
    if (obj === null || obj === undefined) return [];
    return [prefix ? `${prefix}: ${obj}` : String(obj)];
  }

  const API = { VERSION, generate, extract, parseElf, classifyIp, toMarkdown, flattenJson };
  if (typeof module !== "undefined" && module.exports) module.exports = API;
  else root.GPONEngine = API;
})(typeof self !== "undefined" ? self : this);
