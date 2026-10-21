#!/usr/bin/env python3
# bkbn_longitudinal_pull.py — v1.4 (2026-10-21)
# v1.4: manifest and custody CSV record case-relative paths, not absolute paths;
#       change report no longer prints user@host (custody fields stay in sidecars).
# v1.3: default case root moved to ~/Claude/CASE-INTEL/Cases (path change only).
# BWF-PROC tool | Backwater Forensics | case BSP-BKBN-ASN (VRF#26-04-TPWXX)
#
# Longitudinal routing/stewardship observation runs for the BSP-BKBN-ASN 6.3 study.
# Per BWF backbone-data-acquisition standards: raw bytes saved verbatim,
# sidecar metadata, SHA-256 on acquisition, per-case hash registry, custody CSV,
# Src-R-first ordering, bootstrap-selected RDAP endpoints, offline --mock path.
#
# Subcommands:
#   run   — one observation window: IANA bootstraps (Src-R), then per cohort ASN:
#           RIR RDAP autnum (Src-R) -> RIPEstat announced-prefixes, routing-status,
#           asn-neighbours (Src-S); then per watch prefix: RIR RDAP ip (Src-R) ->
#           RIPEstat rpki-validation (Src-S). Writes RUN-<stamp>/ + manifest.
#   diff  — DERIVED ANALYSIS: compare two run manifests, emit change report (.md).
#
# Stdlib only. Runs on stock macOS python3.
#
# Usage:
#   python3 bkbn_longitudinal_pull.py run  --cohort BSP-BKBN-ASN-cohort.json
#   python3 bkbn_longitudinal_pull.py run  --cohort BSP-BKBN-ASN-cohort.json --asn 7046 --asn 7015
#   python3 bkbn_longitudinal_pull.py run  --cohort BSP-BKBN-ASN-cohort.json --mock
#   python3 bkbn_longitudinal_pull.py diff --old <old_manifest.json> --new <new_manifest.json>
#
# Default output root: ~/Claude/CASE-INTEL/Cases/BSP-BKBN-ASN/   (--outdir overrides;
# CASE_INTEL_HOME overrides the ~/Claude/CASE-INTEL root.)

import argparse, csv, getpass, hashlib, ipaddress, json, os, re, socket, sys, time
import urllib.request, urllib.error
from datetime import datetime, timezone

TOOL_NAME = "bkbn_longitudinal_pull.py"
TOOL_VERSION = "1.4"
CASE = "BSP-BKBN-ASN"
REGISTRY_NAME = CASE + "_FILE_HASHES.txt"
CUSTODY_NAME = CASE + "_custody.csv"
USER_AGENT = "BWF-BKBN-acq/1.4 (forensic acquisition; contact: analyst-of-record)"
SOURCEAPP = "bwf-bkbn"

# Exact responding-host -> (SOURCE label, Src tier). Exact match only — never substring.
AUTHORITY_MAP = {
    "data.iana.org":      ("IANA",     "Src-R"),
    "rdap.iana.org":      ("IANA",     "Src-R"),
    "rdap.arin.net":      ("ARIN",     "Src-R"),
    "rdap.db.ripe.net":   ("RIPE-NCC", "Src-R"),
    "rdap.apnic.net":     ("APNIC",    "Src-R"),
    "rdap.afrinic.net":   ("AFRINIC",  "Src-R"),
    "rdap.lacnic.net":    ("LACNIC",   "Src-R"),
    "stat.ripe.net":      ("RIPESTAT", "Src-S"),
    "mock.invalid":       ("MOCK",     "Src-MOCK"),
}

def utcnow():
    return datetime.now(timezone.utc)

def stamp(dt=None):
    return (dt or utcnow()).strftime("%Y%m%d-%H%M%SZ")

def datepart(dt=None):
    return (dt or utcnow()).strftime("%Y-%m-%d")

def hmsz(dt=None):
    return (dt or utcnow()).strftime("%H%M%SZ")

def sha256_file(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()

def sha256_bytes(b):
    return hashlib.sha256(b).hexdigest()

def tool_self_hash():
    try:
        return sha256_file(os.path.abspath(__file__))
    except Exception:
        return "unavailable"

def say(msg):
    # Console is for the analyst's eyes; evidence writing never depends on it.
    try:
        print(msg, flush=True)
    except (BrokenPipeError, OSError):
        pass

def default_outdir():
    root = os.environ.get("CASE_INTEL_HOME",
                          os.path.join(os.path.expanduser("~"), "Claude", "CASE-INTEL"))
    return os.path.join(root, "Cases", CASE)

def safe_target(t):
    return str(t).replace("/", "_").replace(":", ".")

def nonclobber(path):
    if not os.path.exists(path):
        return path
    base, ext = os.path.splitext(path)
    i = 2
    while os.path.exists(f"{base}.v{i}{ext}"):
        i += 1
    return f"{base}.v{i}{ext}"

# ---------------------------------------------------------------- mock corpus
def mock_body(kind, target, variant):
    pfx4 = ["203.0.113.0/24", "198.51.100.0/24"]
    if variant == "B":
        pfx4 = ["203.0.113.0/24", "192.0.2.0/24", "198.18.0.0/15"]
    corpus = {
        "bootstrap_asn": {"description": "MOCK asn bootstrap", "services": [[["0-4294967295"], ["https://mock.invalid/rdap/"]]]},
        "bootstrap_ipv4": {"description": "MOCK ipv4 bootstrap", "services": [[["0.0.0.0/0"], ["https://mock.invalid/rdap/"]]]},
        "bootstrap_ipv6": {"description": "MOCK ipv6 bootstrap", "services": [[["::/0"], ["https://mock.invalid/rdap/"]]]},
        "rdap_autnum": {"objectClassName": "autnum", "handle": f"MOCK-{target}",
                        "name": "MOCK-ASN", "status": ["active"],
                        "events": [{"eventAction": "last changed", "eventDate": "2022-11-02T00:00:00Z"}]},
        "rdap_ip": {"objectClassName": "ip network", "handle": f"MOCK-NET-{safe_target(target)}",
                    "name": "MOCK-NET", "startAddress": "203.0.113.0", "endAddress": "203.0.113.255",
                    "originas": []},
        "announced-prefixes": {"status": "ok", "data": {"resource": str(target),
                               "prefixes": [{"prefix": p} for p in pfx4]}},
        "routing-status": {"status": "ok", "data": {"resource": str(target),
                           "announced_space": {"v4": {"prefixes": len(pfx4)}, "v6": {"prefixes": 1}},
                           "visibility": {"v4": {"ris_peers_seeing": 320 if variant != "B" else 0,
                                                 "total_ris_peers": 326}}}},
        "asn-neighbours": {"status": "ok", "data": {"resource": str(target),
                           "neighbours": [{"asn": 3356, "type": "left"}, {"asn": 1299, "type": "left"}]
                           if variant != "B" else [{"asn": 64512, "type": "left"}]}},
        "rpki-validation": {"status": "ok", "data": {"status": "unknown" if variant != "B" else "invalid_asn",
                            "validating_roas": []}},
        "routing-history": {"status": "ok", "data": {"resource": str(target), "by_origin": [
                            {"origin": str(target).lstrip("AS"), "prefixes": [{"prefix": p, "timelines": []} for p in pfx4]}]}},
    }
    return json.dumps(corpus[kind], indent=1).encode()

# ---------------------------------------------------------------- acquisition
class Acquirer:
    def __init__(self, outdir, rundir, mock=False, mock_variant="A", delay=1.0):
        self.outdir, self.rundir = outdir, rundir
        self.mock, self.mock_variant, self.delay = mock, mock_variant, delay
        self.tool_hash = tool_self_hash()
        self.host = socket.gethostname()
        self.user = getpass.getuser()
        self.records = []   # manifest rows
        os.makedirs(rundir, exist_ok=True)

    def classify(self, final_url):
        host = urllib.request.urlparse(final_url).hostname or ""
        if host in AUTHORITY_MAP:
            return AUTHORITY_MAP[host]
        return (re.sub(r"[^A-Za-z0-9.-]", "", host).upper() or "UNKNOWN", "Src-UNMAPPED")

    def fetch(self, url, kind, target, artifact, basis):
        """Acquire one object: raw bytes + sidecar + hashes + registry + custody."""
        t_req = utcnow()
        if self.mock:
            body = mock_body(kind, target, self.mock_variant)
            status, headers, final_url = 200, {"Date": t_req.strftime("%a, %d %b %Y %H:%M:%S GMT"),
                                               "Content-Type": "application/json",
                                               "X-Mock": "true"}, "https://mock.invalid/" + kind
        else:
            req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT,
                                                       "Accept": "application/rdap+json, application/json"})
            try:
                with urllib.request.urlopen(req, timeout=60) as r:
                    body = r.read()
                    status, final_url = r.status, r.geturl()
                    headers = dict(r.headers)
            except urllib.error.HTTPError as e:
                body = e.read() or b""
                status, final_url, headers = e.code, url, dict(e.headers or {})
            except Exception as e:
                body = json.dumps({"acquisition_error": str(e)}).encode()
                status, final_url, headers = -1, url, {}
        t_resp = utcnow()

        source, tier = self.classify(final_url)
        finding = "PND" if status == 200 else "ANO"
        name = f"{CASE}-{finding}-{datepart(t_req)}_{source}-{artifact}_{safe_target(target)}_{hmsz(t_req)}"
        raw_path = nonclobber(os.path.join(self.rundir, name + ".json"))
        with open(raw_path, "wb") as f:
            f.write(body)                       # raw response bytes, verbatim
        sidecar = {
            "evidence_id": os.path.splitext(os.path.basename(raw_path))[0],
            "case": CASE, "src_tier": tier, "source": source,
            "request_url": url, "final_url": final_url,
            "request_time_utc": t_req.isoformat(), "response_time_utc": t_resp.isoformat(),
            "http_status": status,
            "headers_subset": {k: headers.get(k) for k in ("Date", "Content-Type", "Server", "X-Mock") if headers.get(k)},
            "endpoint_selection_basis": basis,
            "tool": {"name": TOOL_NAME, "version": TOOL_VERSION, "sha256": self.tool_hash},
            "acquired_by": {"user": self.user, "host": self.host},
            "mock": bool(self.mock),
            "sha256_raw": sha256_bytes(body),
        }
        meta_path = raw_path + ".meta.json"
        with open(meta_path, "w") as f:
            json.dump(sidecar, f, indent=1)
        for p in (raw_path, meta_path):
            with open(os.path.join(self.outdir, REGISTRY_NAME), "a") as reg:
                reg.write(f"{sha256_file(p)}  {os.path.relpath(p, self.outdir)}\n")
        cpath = os.path.join(self.outdir, CUSTODY_NAME)
        newfile = not os.path.exists(cpath)
        with open(cpath, "a", newline="") as f:
            w = csv.writer(f)
            if newfile:
                w.writerow(["utc", "evidence_id", "sha256", "src_tier", "source", "artifact",
                            "target", "http_status", "url", "tool", "tool_sha256", "user", "host", "mock"])
            w.writerow([t_resp.isoformat(), sidecar["evidence_id"], sidecar["sha256_raw"], tier, source,
                        artifact, target, status, final_url, f"{TOOL_NAME} v{TOOL_VERSION}",
                        self.tool_hash, self.user, self.host, self.mock])
        rec = {"evidence_id": sidecar["evidence_id"], "kind": kind, "target": str(target),
               "src_tier": tier, "source": source, "status": status, "sha256": sidecar["sha256_raw"],
               "path": os.path.relpath(raw_path, self.outdir)}
        self.records.append(rec)
        say(f"  [{tier:>6}] {sidecar['evidence_id']}  (HTTP {status})")
        if not self.mock:
            time.sleep(self.delay)
        try:
            return json.loads(body)
        except Exception:
            return None

# ----------------------------------------------------- bootstrap endpoint pick
def pick_asn_service(bootstrap, asn):
    try:
        for entry in bootstrap["services"]:
            ranges, urls = entry[0], entry[1]
            for r in ranges:
                lo, _, hi = r.partition("-")
                if int(lo) <= asn <= int(hi or lo):
                    return urls[0].rstrip("/") + "/", f"IANA asn.json range {r}"
    except Exception:
        pass
    return "https://rdap.arin.net/registry/", "fallback: ARIN (bootstrap parse failed)"

def pick_ip_service(bootstrap, prefix):
    try:
        net = ipaddress.ip_network(prefix, strict=False)
        best, best_url, best_r = -1, None, None
        for entry in bootstrap["services"]:
            ranges, urls = entry[0], entry[1]
            for r in ranges:
                try:
                    cand = ipaddress.ip_network(r)
                except ValueError:
                    continue
                if net.version == cand.version and net.subnet_of(cand) and cand.prefixlen > best:
                    best, best_url, best_r = cand.prefixlen, urls[0].rstrip("/") + "/", r
        if best_url:
            return best_url, f"IANA ip bootstrap {best_r}"
    except Exception:
        pass
    return "https://rdap.arin.net/registry/", "fallback: ARIN (bootstrap parse failed)"

# ------------------------------------------------------------------- run mode
def cmd_run(a):
    outdir = os.path.abspath(a.outdir or default_outdir())
    os.makedirs(outdir, exist_ok=True)
    with open(a.cohort) as f:
        cohort = json.load(f)
    asns = [x for x in cohort["asns"] if (not a.asn or x["asn"] in a.asn)]
    watch = [] if a.skip_prefix_checks else [
        w for w in cohort.get("watch_prefixes", []) if not w["prefix"].startswith("FILL-ME")]
    skipped = [w["prefix"] for w in cohort.get("watch_prefixes", []) if w["prefix"].startswith("FILL-ME")]

    run_id = f"RUN-{stamp()}" + ("-MOCK" if a.mock else "")
    rundir = os.path.join(outdir, run_id)
    acq = Acquirer(outdir, rundir, mock=a.mock, mock_variant=a.mock_variant, delay=a.delay)
    say(f"{run_id}  case={CASE}  cohort={cohort.get('cohort_name')}  asns={len(asns)}  "
        f"watch_prefixes={len(watch)}  mock={a.mock}")
    if skipped:
        say(f"  note: {len(skipped)} watch prefixes skipped (FILL-ME placeholders): {', '.join(skipped)}")

    # Src-R first: IANA bootstraps for the whole run.
    bs_asn = acq.fetch("https://data.iana.org/rdap/asn.json", "bootstrap_asn", "asn-bootstrap",
                       "RDAP-bootstrap", "IANA authoritative RDAP bootstrap (Src-R-first rule)")
    bs_v4 = bs_v6 = None
    if watch:
        bs_v4 = acq.fetch("https://data.iana.org/rdap/ipv4.json", "bootstrap_ipv4", "ipv4-bootstrap",
                          "RDAP-bootstrap", "IANA authoritative RDAP bootstrap (Src-R-first rule)")
        bs_v6 = acq.fetch("https://data.iana.org/rdap/ipv6.json", "bootstrap_ipv6", "ipv6-bootstrap",
                          "RDAP-bootstrap", "IANA authoritative RDAP bootstrap (Src-R-first rule)")

    asn_summaries = {}
    for item in asns:
        asn = item["asn"]
        say(f"AS{asn} ({item.get('arm','?')}) — {item.get('entity','')}")
        base, basis = pick_asn_service(bs_asn or {}, asn)
        rdap = acq.fetch(f"{base}autnum/{asn}", "rdap_autnum", f"AS{asn}", "RDAP", basis)
        ann  = acq.fetch(f"https://stat.ripe.net/data/announced-prefixes/data.json?resource=AS{asn}&sourceapp={SOURCEAPP}",
                         "announced-prefixes", f"AS{asn}", "BGP-prefixes", "RIPEstat Data API (RIS)")
        rst  = acq.fetch(f"https://stat.ripe.net/data/routing-status/data.json?resource=AS{asn}&sourceapp={SOURCEAPP}",
                         "routing-status", f"AS{asn}", "BGP-status", "RIPEstat Data API (RIS)")
        nbr  = acq.fetch(f"https://stat.ripe.net/data/asn-neighbours/data.json?resource=AS{asn}&sourceapp={SOURCEAPP}",
                         "asn-neighbours", f"AS{asn}", "BGP-neighbours", "RIPEstat Data API (RIS)")
        if a.history:
            acq.fetch(f"https://stat.ripe.net/data/routing-history/data.json?resource=AS{asn}"
                      f"&starttime={a.history_start}&endtime={a.history_end}&sourceapp={SOURCEAPP}",
                      "routing-history", f"AS{asn}", "BGP-history",
                      f"RIPEstat Data API (RIS history {a.history_start}..{a.history_end})")
        prefixes = sorted(p.get("prefix", "") for p in (((ann or {}).get("data") or {}).get("prefixes") or []))
        neigh = sorted({str(n.get("asn")) for n in (((nbr or {}).get("data") or {}).get("neighbours") or [])})
        vis = (((rst or {}).get("data") or {}).get("visibility") or {})
        asn_summaries[str(asn)] = {
            "arm": item.get("arm"), "entity": item.get("entity"),
            "prefix_count": len(prefixes),
            "prefix_set_sha256": sha256_bytes("\n".join(prefixes).encode()),
            "prefixes": prefixes,
            "neighbour_set": neigh,
            "visibility_v4": vis.get("v4"),
            "rdap_handle": (rdap or {}).get("handle"),
            "rdap_status": (rdap or {}).get("status"),
        }

    prefix_summaries = {}
    for w in watch:
        pfx = w["prefix"]
        say(f"watch prefix {pfx} — {w.get('label','')}")
        bs = bs_v6 if ":" in pfx else bs_v4
        base, basis = pick_ip_service(bs or {}, pfx)
        ipq = pfx.split("/")[0] if a.mock else pfx
        rdap_ip = acq.fetch(f"{base}ip/{ipq}", "rdap_ip", pfx, "RDAP", basis)
        origin = w.get("expect_origin_asn")
        rpki = acq.fetch(f"https://stat.ripe.net/data/rpki-validation/data.json?resource=AS{origin}"
                         f"&prefix={urllib.request.quote(pfx, safe='')}&sourceapp={SOURCEAPP}",
                         "rpki-validation", pfx, "RPKI", "RIPEstat Data API (RPKI validator)")
        prefix_summaries[pfx] = {
            "label": w.get("label"), "expect_origin_asn": origin,
            "rdap_handle": (rdap_ip or {}).get("handle"),
            "rdap_originas": (rdap_ip or {}).get("originas", "FIELD-ABSENT"),
            "rpki_status": (((rpki or {}).get("data") or {}).get("status")),
        }

    manifest = {
        "derived": True,
        "note": "DERIVED run manifest — analysis aid citing evidence IDs; the raw files are the evidence.",
        "run_id": run_id, "case": CASE, "utc": utcnow().isoformat(), "mock": a.mock,
        "cohort_file": os.path.basename(a.cohort), "cohort_sha256": sha256_file(a.cohort),
        "tool": {"name": TOOL_NAME, "version": TOOL_VERSION, "sha256": acq.tool_hash},
        "skipped_fillme_prefixes": skipped,
        "asn_summaries": asn_summaries, "prefix_summaries": prefix_summaries,
        "evidence": acq.records,
    }
    mpath = os.path.join(rundir, f"{run_id}_manifest.json")
    with open(mpath, "w") as f:
        json.dump(manifest, f, indent=1)
    with open(os.path.join(outdir, CUSTODY_NAME), "a", newline="") as f:
        csv.writer(f).writerow([utcnow().isoformat(), f"{run_id}_manifest", sha256_file(mpath),
                                "DERIVED", "ANALYST-TOOL", "manifest", run_id, "", os.path.relpath(mpath, outdir),
                                f"{TOOL_NAME} v{TOOL_VERSION}", acq.tool_hash, acq.user, acq.host, a.mock])
    say(f"done: {len(acq.records)} evidence files in {rundir}")
    say(f"manifest: {mpath}")
    say(f"registry: {os.path.join(outdir, REGISTRY_NAME)}")

# ------------------------------------------------------------------ diff mode
def cmd_diff(a):
    with open(a.old) as f: old = json.load(f)
    with open(a.new) as f: new = json.load(f)
    lines = [
        f"# {CASE} 6.3 CHANGE REPORT — DERIVED ANALYSIS",
        f"### INFRA-PATCH-MAPPING | VRF#26-04-TPWXX",
        f"**Generated {utcnow().isoformat()} by {TOOL_NAME} v{TOOL_VERSION} (sha256 {tool_self_hash()[:16]}…)**",
        "",
        f"Old run: `{old['run_id']}` ({old['utc']}) | New run: `{new['run_id']}` ({new['utc']})",
        "",
        "This report is derived analysis. Every change cites run manifests; the raw files",
        "named in those manifests are the evidence. Mock runs are not evidence.",
        "",
        "## Instrument check (controls first)",
        "",
        "| ASN | arm | old prefix count | new prefix count | old v4 visibility | new v4 visibility |",
        "|---|---|---|---|---|---|",
    ]
    def vis(s):
        v = (s or {}).get("visibility_v4") or {}
        seen, tot = v.get("ris_peers_seeing"), v.get("total_ris_peers")
        return f"{seen}/{tot}" if seen is not None else "n/a"
    oldA, newA = old["asn_summaries"], new["asn_summaries"]
    control_dark = []
    for asn in sorted(set(oldA) | set(newA), key=int):
        o, n = oldA.get(asn), newA.get(asn)
        if not (o and n): continue
        if o.get("arm") == "control":
            lines.append(f"| AS{asn} | control | {o['prefix_count']} | {n['prefix_count']} | {vis(o)} | {vis(n)} |")
            ov = ((o.get('visibility_v4') or {}).get('ris_peers_seeing') or 0)
            nv = ((n.get('visibility_v4') or {}).get('ris_peers_seeing') or 0)
            if ov and nv == 0:
                control_dark.append(asn)
    lines += ["",
        ("**INSTRUMENT EVENT CANDIDATE** — control ASN(s) lost visibility: "
         + ", ".join("AS"+x for x in control_dark)
         + ". Treat every change below as unconfirmed until the instrument is cleared "
           "(second instrument: RouteViews MRT).") if control_dark else
        "Controls stable — no instrument event indicated this window.",
        "", "## Per-ASN changes", ""]
    any_change = False
    for asn in sorted(set(oldA) | set(newA), key=int):
        o, n = oldA.get(asn), newA.get(asn)
        if not (o and n):
            lines.append(f"### AS{asn} — present in only one run"); any_change = True; continue
        chg = []
        if o["prefix_set_sha256"] != n["prefix_set_sha256"]:
            added = sorted(set(n["prefixes"]) - set(o["prefixes"]))
            removed = sorted(set(o["prefixes"]) - set(n["prefixes"]))
            chg.append(f"prefix set changed ({o['prefix_count']} → {n['prefix_count']}): "
                       f"+{len(added)} / −{len(removed)}")
            if added:   chg.append("added: " + ", ".join(added[:25]) + (" …" if len(added) > 25 else ""))
            if removed: chg.append("removed: " + ", ".join(removed[:25]) + (" …" if len(removed) > 25 else ""))
        if o["neighbour_set"] != n["neighbour_set"]:
            chg.append(f"neighbour set changed: {sorted(o['neighbour_set'])} → {sorted(n['neighbour_set'])}")
        if vis(o) != vis(n):
            chg.append(f"v4 visibility changed: {vis(o)} → {vis(n)}")
        if o.get("rdap_handle") != n.get("rdap_handle") or o.get("rdap_status") != n.get("rdap_status"):
            chg.append(f"RDAP handle/status changed: {o.get('rdap_handle')}/{o.get('rdap_status')} → "
                       f"{n.get('rdap_handle')}/{n.get('rdap_status')}")
        if chg:
            any_change = True
            lines.append(f"### AS{asn} ({n.get('arm')}) — {n.get('entity','')}")
            lines += [f"- {c}" for c in chg]
            lines.append("")
    oldP, newP = old.get("prefix_summaries", {}), new.get("prefix_summaries", {})
    wl = []
    for pfx in sorted(set(oldP) | set(newP)):
        o, n = oldP.get(pfx), newP.get(pfx)
        if o and n and (o.get("rpki_status") != n.get("rpki_status")
                        or o.get("rdap_originas") != n.get("rdap_originas")
                        or o.get("rdap_handle") != n.get("rdap_handle")):
            wl.append(f"- `{pfx}` ({(n or o).get('label')}): rpki {o.get('rpki_status')} → {n.get('rpki_status')}; "
                      f"originas {o.get('rdap_originas')} → {n.get('rdap_originas')}; "
                      f"rdap {o.get('rdap_handle')} → {n.get('rdap_handle')}")
    if wl:
        any_change = True
        lines += ["## Watch-prefix changes", ""] + wl + [""]
    if not any_change:
        lines += ["No changes detected between runs (NEG result — a stable window is a result).", ""]
    lines += ["---", f"*VRF#26-04-TPWXX | Backwater Forensics | {datepart()}*"]
    outp = a.out or nonclobber(os.path.join(
        os.path.dirname(os.path.abspath(a.new)),
        f"{CASE}-CHG-{datepart()}_ANALYST-BGP_diff-{old['run_id']}-vs-{new['run_id']}.md"))
    with open(outp, "w") as f:
        f.write("\n".join(lines) + "\n")
    say(f"change report: {outp}")
    say(f"sha256: {sha256_file(outp)}")

def main():
    ap = argparse.ArgumentParser(prog=TOOL_NAME,
        description="BWF BSP-BKBN-ASN 6.3 longitudinal acquisition (raw, hashed, sidecarred).")
    sub = ap.add_subparsers(dest="cmd", required=True)
    r = sub.add_parser("run", help="one observation window over the cohort")
    r.add_argument("--cohort", required=True)
    r.add_argument("--outdir", default=None, help=f"default: {default_outdir()}")
    r.add_argument("--asn", type=int, action="append", help="limit to these ASNs (repeatable)")
    r.add_argument("--skip-prefix-checks", action="store_true")
    r.add_argument("--delay", type=float, default=1.0, help="seconds between live calls (default 1.0)")
    r.add_argument("--mock", action="store_true", help="offline test: canned responses, no network, labeled MOCK")
    r.add_argument("--mock-variant", choices=["A", "B"], default="A", help="mock dataset (B simulates change/dark)")
    r.add_argument("--history", action="store_true",
                   help="also acquire RIPEstat routing-history per ASN (backfill / dark-window checks)")
    r.add_argument("--history-start", default="2026-05-01T00:00",
                   help="routing-history starttime (default 2026-05-01T00:00)")
    r.add_argument("--history-end", default="2026-10-19T00:00",
                   help="routing-history endtime (default 2026-10-19T00:00)")
    r.set_defaults(fn=cmd_run)
    d = sub.add_parser("diff", help="DERIVED change report between two run manifests")
    d.add_argument("--old", required=True)
    d.add_argument("--new", required=True)
    d.add_argument("--out", default=None)
    d.set_defaults(fn=cmd_diff)
    a = ap.parse_args()
    a.fn(a)

if __name__ == "__main__":
    main()
