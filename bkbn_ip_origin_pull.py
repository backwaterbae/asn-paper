#!/usr/bin/env python3
# bkbn_ip_origin_pull.py — v1.3 (2026-10-21)
# v1.3: derived summary no longer prints user@host (custody fields stay in sidecars
#       and the custody CSV, where the acquisition standard requires them).
# v1.2: default case root moved to ~/Claude/CASE-INTEL/Cases (path change only).
# v1.1: origin-at-observation counts ONLY prefixes that cover the address (v1.0
#       counted every origin seen under the queried prefix); when the address is
#       unrouted today, routing-history is queried on the RIR's registered CIDR
#       (RDAP cidr0) instead of being skipped.
# BWF-PROC tool | Backwater Forensics | case BSP-BKBN-ASN (VRF#26-04-TPWXX)
#
# Origin-ASN lookup for individual IP addresses at a stated observation date.
# Built to close the paper's open item: which networks originated the
# sandbox-observed bybanking.com addresses (validation data, Section 3.7).
#
# Per address, in this order (Src-R first):
#   1. IANA RDAP bootstrap (ipv4/ipv6, asn)       Src-R, once per run
#   2. RIR RDAP ip  -> registrant of the address  Src-R
#   3. RIPEstat network-info -> covering prefix + origin ASN(s) today   Src-S
#   4. RIPEstat routing-history on that prefix, window = observation date
#      +/- --window-days -> origin ASN(s) AT THE TIME OBSERVED          Src-S
#   5. RIR RDAP autnum for every origin ASN found -> ASN holder          Src-R
# Writes raw response bytes verbatim, a .meta.json sidecar per file, SHA-256
# to the case registry, a custody CSV row per file, and a DERIVED summary.
#
# All endpoints are neutral public registries/aggregators. Nothing here
# touches the subject's infrastructure. MacBook Terminal is fine.
#
# Usage:
#   python3 bkbn_ip_origin_pull.py --ip 148.17.131.206@2026-02-09 \
#                                  --ip 123.150.3.39@2026-07-25 \
#                                  --ip <NL-address>@2026-07-25
#   python3 bkbn_ip_origin_pull.py --ip ... --mock         (offline self-test)
#   options: --window-days 3  --outdir DIR  --delay 1.0  --flag-asn 7046
#
# Default output: ~/Claude/CASE-INTEL/Cases/BSP-BKBN-ASN/IPORIGIN-<stamp>/
# (CASE_INTEL_HOME overrides the ~/Claude/CASE-INTEL root; --outdir overrides the case folder).
# Stdlib only. Runs on stock macOS python3.

import argparse, csv, getpass, hashlib, ipaddress, json, os, re, socket, sys, time
import urllib.request, urllib.error, urllib.parse
from datetime import datetime, timezone, timedelta

TOOL_NAME = "bkbn_ip_origin_pull.py"
TOOL_VERSION = "1.3"
CASE = "BSP-BKBN-ASN"
REGISTRY_NAME = CASE + "_FILE_HASHES.txt"
CUSTODY_NAME = CASE + "_custody.csv"
USER_AGENT = "BWF-BKBN-iporigin/1.3 (forensic acquisition; contact: analyst-of-record)"
SOURCEAPP = "bwf-bkbn"

AUTHORITY_MAP = {  # exact responding host -> (SOURCE label, Src tier)
    "data.iana.org":    ("IANA", "Src-R"),
    "rdap.iana.org":    ("IANA", "Src-R"),
    "rdap.arin.net":    ("ARIN", "Src-R"),
    "rdap.db.ripe.net": ("RIPE-NCC", "Src-R"),
    "rdap.apnic.net":   ("APNIC", "Src-R"),
    "rdap.afrinic.net": ("AFRINIC", "Src-R"),
    "rdap.lacnic.net":  ("LACNIC", "Src-R"),
    "stat.ripe.net":    ("RIPESTAT", "Src-S"),
    "mock.invalid":     ("MOCK", "Src-MOCK"),
}

def utcnow(): return datetime.now(timezone.utc)
def sha256_bytes(b): return hashlib.sha256(b).hexdigest()
def sha256_file(p):
    h = hashlib.sha256()
    with open(p, "rb") as f:
        for c in iter(lambda: f.read(65536), b""): h.update(c)
    return h.hexdigest()
def tool_hash():
    try: return sha256_file(os.path.abspath(__file__))
    except Exception: return "unavailable"
def say(m):
    try: print(m, flush=True)
    except (BrokenPipeError, OSError): pass
def safe(t): return re.sub(r"[^A-Za-z0-9._-]", "_", str(t).replace("/", "_").replace(":", "."))
def nonclobber(p):
    if not os.path.exists(p): return p
    b, e = os.path.splitext(p); i = 2
    while os.path.exists(f"{b}.v{i}{e}"): i += 1
    return f"{b}.v{i}{e}"
def default_case_dir():
    root = os.environ.get("CASE_INTEL_HOME", os.path.join(os.path.expanduser("~"), "Claude", "CASE-INTEL"))
    return os.path.join(root, "Cases", CASE)

# ------------------------------------------------------------------ mock data
MOCK_PREFIX = {"148.17.131.206": ("", ""),                 # unrouted today
               "148.16.0.0/12":  ("148.16.0.0/12", "64500"),  # registered CIDR
               "123.150.3.39":   ("123.150.0.0/16", "64501")}
def mock_body(kind, target):
    t = str(target)
    by_pfx = {v[0]: v for v in MOCK_PREFIX.values()}
    pfx, asn = MOCK_PREFIX.get(t) or by_pfx.get(t) or ("198.51.100.0/24", "64502")
    if kind == "bootstrap_ip":
        return {"services": [[["0.0.0.0/0", "::/0"], ["https://mock.invalid/rdap/"]]]}
    if kind == "bootstrap_asn":
        return {"services": [[["0-4294967295"], ["https://mock.invalid/rdap/"]]]}
    if kind == "rdap_ip":
        return {"objectClassName": "ip network", "handle": f"MOCK-{safe(t)}", "name": "MOCK-NET",
                "cidr0_cidrs": [{"v4prefix": "148.16.0.0", "length": 12}] if t.startswith("148.") else [],
                "entities": [{"roles": ["registrant"], "vcardArray": ["vcard", [["fn", {}, "text", "Mock Registrant"]]]}]}
    if kind == "network-info":
        return {"status": "ok", "data": {"asns": [asn] if asn else [], "prefix": pfx}}
    if kind == "routing-history":
        return {"status": "ok", "data": {"by_origin": [
            {"origin": asn, "prefixes": [{"prefix": pfx, "timelines": [
                {"starttime": "2026-01-01T00:00:00", "endtime": "2026-10-01T00:00:00", "full_peers_seeing": 320}]}]},
            {"origin": "64999", "prefixes": [{"prefix": "203.0.113.0/24", "timelines": [   # non-covering decoy
                {"starttime": "2026-01-01T00:00:00", "endtime": "2026-10-01T00:00:00", "full_peers_seeing": 320}]}]}]}}
    if kind == "rdap_autnum":
        return {"objectClassName": "autnum", "handle": f"AS{t.lstrip('AS')}", "name": "MOCK-ASN-NAME",
                "entities": [{"roles": ["registrant"], "vcardArray": ["vcard", [["fn", {}, "text", "Mock Network Operator"]]]}]}
    raise KeyError(kind)

# --------------------------------------------------------------- acquisition
class Acq:
    def __init__(self, case_dir, run_dir, mock, delay):
        self.case_dir, self.run_dir, self.mock, self.delay = case_dir, run_dir, mock, delay
        self.th, self.user, self.host = tool_hash(), getpass.getuser(), socket.gethostname()
        self.records = []
        os.makedirs(run_dir, exist_ok=True)

    def fetch(self, url, kind, target, artifact, basis):
        t0 = utcnow()
        if self.mock:
            body = json.dumps(mock_body(kind, target), indent=1).encode()
            status, final, hdr = 200, "https://mock.invalid/" + kind, {"X-Mock": "true",
                     "Date": t0.strftime("%a, %d %b %Y %H:%M:%S GMT")}
        else:
            req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT,
                                                       "Accept": "application/rdap+json, application/json"})
            try:
                with urllib.request.urlopen(req, timeout=60) as r:
                    body, status, final, hdr = r.read(), r.status, r.geturl(), dict(r.headers)
            except urllib.error.HTTPError as e:
                body, status, final, hdr = (e.read() or b""), e.code, url, dict(e.headers or {})
            except Exception as e:
                body, status, final, hdr = json.dumps({"acquisition_error": str(e)}).encode(), -1, url, {}
        t1 = utcnow()
        host = urllib.parse.urlparse(final).hostname or ""
        source, tier = AUTHORITY_MAP.get(host, (re.sub(r"[^A-Za-z0-9.-]", "", host).upper() or "UNKNOWN", "Src-UNMAPPED"))
        finding = "PND" if status == 200 else "ANO"
        name = f"{CASE}-{finding}-{t0:%Y-%m-%d}_{source}-{artifact}_{safe(target)}_{t0:%H%M%SZ}"
        raw = nonclobber(os.path.join(self.run_dir, name + ".json"))
        with open(raw, "wb") as f: f.write(body)
        side = {"evidence_id": os.path.splitext(os.path.basename(raw))[0], "case": CASE, "src_tier": tier,
                "source": source, "request_url": url, "final_url": final,
                "request_time_utc": t0.isoformat(), "response_time_utc": t1.isoformat(), "http_status": status,
                "headers_subset": {k: hdr.get(k) for k in ("Date", "Content-Type", "Server", "X-Mock") if hdr.get(k)},
                "endpoint_selection_basis": basis,
                "tool": {"name": TOOL_NAME, "version": TOOL_VERSION, "sha256": self.th},
                "acquired_by": {"user": self.user, "host": self.host}, "mock": self.mock,
                "sha256_raw": sha256_bytes(body)}
        meta = raw + ".meta.json"
        with open(meta, "w") as f: json.dump(side, f, indent=1)
        with open(os.path.join(self.case_dir, REGISTRY_NAME), "a") as reg:
            for p in (raw, meta): reg.write(f"{sha256_file(p)}  {os.path.relpath(p, self.case_dir)}\n")
        cp = os.path.join(self.case_dir, CUSTODY_NAME); new = not os.path.exists(cp)
        with open(cp, "a", newline="") as f:
            w = csv.writer(f)
            if new: w.writerow(["utc", "evidence_id", "sha256", "src_tier", "source", "artifact", "target",
                                "http_status", "url", "tool", "tool_sha256", "user", "host", "mock"])
            w.writerow([t1.isoformat(), side["evidence_id"], side["sha256_raw"], tier, source, artifact, target,
                        status, final, f"{TOOL_NAME} v{TOOL_VERSION}", self.th, self.user, self.host, self.mock])
        self.records.append({"evidence_id": side["evidence_id"], "kind": kind, "target": str(target),
                             "src_tier": tier, "status": status, "sha256": side["sha256_raw"]})
        say(f"  [{tier:>8}] {side['evidence_id']}  (HTTP {status})")
        if not self.mock: time.sleep(self.delay)
        try: return json.loads(body)
        except Exception: return None

# ------------------------------------------------------------------- helpers
def pick_ip_base(bs, ip):
    try:
        a = ipaddress.ip_address(ip); best = (-1, None, None)
        for rngs, urls in ((e[0], e[1]) for e in bs["services"]):
            for r in rngs:
                try: n = ipaddress.ip_network(r)
                except ValueError: continue
                if a.version == n.version and a in n and n.prefixlen > best[0]:
                    best = (n.prefixlen, urls[0].rstrip("/") + "/", r)
        if best[1]: return best[1], f"IANA ip bootstrap {best[2]}"
    except Exception: pass
    return "https://rdap.arin.net/registry/", "fallback: ARIN (bootstrap parse failed)"

def pick_asn_base(bs, asn):
    try:
        for rngs, urls in ((e[0], e[1]) for e in bs["services"]):
            for r in rngs:
                lo, _, hi = r.partition("-")
                if int(lo) <= asn <= int(hi or lo): return urls[0].rstrip("/") + "/", f"IANA asn.json {r}"
    except Exception: pass
    return "https://rdap.arin.net/registry/", "fallback: ARIN (bootstrap parse failed)"

def registrant(rdap):
    def walk(ents):
        for e in ents or []:
            if "registrant" in (e.get("roles") or []):
                for item in ((e.get("vcardArray") or [None, []])[1] or []):
                    if item and item[0] == "fn": return item[3]
            r = walk(e.get("entities"))
            if r: return r
        return None
    if not isinstance(rdap, dict): return None
    return walk(rdap.get("entities")) or rdap.get("name")

def origins_in_window(rh, start, end, ip):
    """Origins of prefixes that COVER ip and were visible in [start, end]."""
    out, cov = set(), set()
    a = ipaddress.ip_address(ip)
    for o in (((rh or {}).get("data") or {}).get("by_origin") or []):
        for p in o.get("prefixes") or []:
            try:
                if a not in ipaddress.ip_network(p.get("prefix", ""), strict=False): continue
            except ValueError: continue
            for tl in p.get("timelines") or []:
                try:
                    s = datetime.fromisoformat(tl["starttime"]).replace(tzinfo=timezone.utc)
                    e = datetime.fromisoformat(tl["endtime"]).replace(tzinfo=timezone.utc)
                except Exception: continue
                if s <= end and e >= start:
                    out.add(str(o.get("origin"))); cov.add(p["prefix"])
    return sorted(out), sorted(cov, key=lambda x: ipaddress.ip_network(x).prefixlen, reverse=True)

def registered_cidr(rdap, ip):
    """Most-specific RIR-registered CIDR (RDAP cidr0) containing ip."""
    a, best = ipaddress.ip_address(ip), None
    for c in (rdap or {}).get("cidr0_cidrs") or []:
        base = c.get("v4prefix") or c.get("v6prefix")
        try: n = ipaddress.ip_network(f"{base}/{c.get('length')}")
        except ValueError: continue
        if a in n and (best is None or n.prefixlen > best.prefixlen): best = n
    return str(best) if best else None

# ---------------------------------------------------------------------- main
def main():
    ap = argparse.ArgumentParser(prog=TOOL_NAME, description="Origin ASN of IPs at an observation date (raw, hashed).")
    ap.add_argument("--ip", action="append", required=True, help="IP@YYYY-MM-DD (repeatable)")
    ap.add_argument("--window-days", type=int, default=3)
    ap.add_argument("--flag-asn", type=int, default=7046, help="ASN to compare against (default 7046)")
    ap.add_argument("--outdir", default=None, help=f"case folder (default {default_case_dir()})")
    ap.add_argument("--delay", type=float, default=1.0)
    ap.add_argument("--mock", action="store_true", help="offline self-test; MOCK-labeled, never evidence")
    a = ap.parse_args()

    targets = []
    for spec in a.ip:
        ip, _, d = spec.partition("@")
        try:
            ipaddress.ip_address(ip); obs = datetime.strptime(d, "%Y-%m-%d").replace(tzinfo=timezone.utc)
        except ValueError:
            sys.exit(f"bad --ip '{spec}': use IP@YYYY-MM-DD")
        targets.append((ip, obs))

    case_dir = os.path.abspath(a.outdir or default_case_dir()); os.makedirs(case_dir, exist_ok=True)
    run_id = f"IPORIGIN-{utcnow():%Y%m%d-%H%M%SZ}" + ("-MOCK" if a.mock else "")
    acq = Acq(case_dir, os.path.join(case_dir, run_id), a.mock, a.delay)
    say(f"{run_id}  case={CASE}  addresses={len(targets)}  window=±{a.window_days}d  mock={a.mock}")

    bs4 = acq.fetch("https://data.iana.org/rdap/ipv4.json", "bootstrap_ip", "ipv4-bootstrap", "RDAP-bootstrap", "IANA RDAP bootstrap (Src-R first)")
    bs6 = acq.fetch("https://data.iana.org/rdap/ipv6.json", "bootstrap_ip", "ipv6-bootstrap", "RDAP-bootstrap", "IANA RDAP bootstrap (Src-R first)") \
          if any(":" in ip for ip, _ in targets) else None
    bsa = acq.fetch("https://data.iana.org/rdap/asn.json", "bootstrap_asn", "asn-bootstrap", "RDAP-bootstrap", "IANA RDAP bootstrap (Src-R first)")

    rows, asn_names = [], {}
    for ip, obs in targets:
        say(f"{ip}  observed {obs:%Y-%m-%d}")
        base, basis = pick_ip_base((bs6 if ":" in ip else bs4) or {}, ip)
        rd = acq.fetch(f"{base}ip/{ip}", "rdap_ip", ip, "RDAP", basis)
        ni = acq.fetch(f"https://stat.ripe.net/data/network-info/data.json?resource={ip}&sourceapp={SOURCEAPP}",
                       "network-info", ip, "BGP-netinfo", "RIPEstat Data API (RIS), current")
        prefix = ((ni or {}).get("data") or {}).get("prefix")
        now_asns = sorted(str(x) for x in (((ni or {}).get("data") or {}).get("asns") or []))
        start, end = obs - timedelta(days=a.window_days), obs + timedelta(days=a.window_days)
        then_asns, then_pfx = [], []
        hist_res, hist_basis = prefix, "covering prefix announced today (RIPEstat network-info)"
        if not prefix:
            hist_res = registered_cidr(rd, ip)
            hist_basis = "unrouted today; RIR-registered CIDR from RDAP cidr0"
            say(f"  unrouted today; querying history on registered CIDR {hist_res}")
        if hist_res:
            rh = acq.fetch(f"https://stat.ripe.net/data/routing-history/data.json?resource={urllib.parse.quote(hist_res, safe='')}"
                           f"&starttime={start:%Y-%m-%dT%H:%M}&endtime={end:%Y-%m-%dT%H:%M}&sourceapp={SOURCEAPP}",
                           "routing-history", hist_res, "BGP-history",
                           f"RIPEstat routing-history, window {start:%Y-%m-%d}..{end:%Y-%m-%d}; {hist_basis}")
            then_asns, then_pfx = origins_in_window(rh, start, end, ip)
        else:
            say("  unrouted today and no registered CIDR in RDAP; history not queried")
        for asn in sorted(set(now_asns) | set(then_asns)):
            if asn not in asn_names and asn.isdigit():
                b, bb = pick_asn_base(bsa or {}, int(asn))
                asn_names[asn] = registrant(acq.fetch(f"{b}autnum/{asn}", "rdap_autnum", f"AS{asn}", "RDAP", bb)) or "(no registrant in record)"
        rows.append({"ip": ip, "observed": f"{obs:%Y-%m-%d}", "ip_registrant": registrant(rd) or "(none in record)",
                     "covering_prefix_now": prefix, "history_resource": hist_res,
                     "covering_prefixes_at_observation": then_pfx,
                     "origin_now": now_asns, "origin_at_observation": then_asns,
                     "flag_asn_at_observation": str(a.flag_asn) in then_asns})

    lines = [f"# {CASE} IP ORIGIN CHECK — DERIVED SUMMARY", "### INFRA-PATCH-MAPPING | VRF#26-04-TPWXX",
             f"**{run_id} | {TOOL_NAME} v{TOOL_VERSION} (sha256 {acq.th[:16]}…)**", "",
             "Derived analysis. The raw files in this run folder are the evidence." + (" MOCK RUN — NOT EVIDENCE." if a.mock else ""), "",
             f"| IP | Observed | IP registrant (RIR) | Covering prefix(es) at observation | Origin ASN at observation (±{a.window_days}d) | Covering prefix now | Origin ASN now | AS{a.flag_asn} at observation? |",
             "|---|---|---|---|---|---|---|---|"]
    fmt = lambda xs: ", ".join(f"AS{x} ({asn_names.get(x, '?')})" for x in xs) or "none in window"
    for r in rows:
        lines.append(f"| `{r['ip']}` | {r['observed']} | {r['ip_registrant']} | {', '.join(r['covering_prefixes_at_observation']) or 'none announced'} | "
                     f"{fmt(r['origin_at_observation'])} | {r['covering_prefix_now'] or 'not routed now'} | {fmt(r['origin_now'])} | "
                     f"{'YES' if r['flag_asn_at_observation'] else 'no'} |")
    lines += ["", "Read origin-at-observation, not origin-now, for the paper's claim. Only prefixes that cover the address are "
              "counted. 'none in window' / 'none announced' means RIS saw no announcement covering the address in that window "
              "(the address was unrouted, as seen by RIS) — check the raw routing-history before drawing a conclusion.", "",
              f"*VRF#26-04-TPWXX | Backwater Forensics | {utcnow():%Y-%m-%d}*"]
    summ = os.path.join(acq.run_dir, f"{CASE}-PND-{utcnow():%Y-%m-%d}_ANALYST-IPORIGIN-summary.md")
    with open(summ, "w") as f: f.write("\n".join(lines) + "\n")
    man = os.path.join(acq.run_dir, f"{run_id}_manifest.json")
    with open(man, "w") as f:
        json.dump({"derived": True, "run_id": run_id, "tool": {"name": TOOL_NAME, "version": TOOL_VERSION, "sha256": acq.th},
                   "mock": a.mock, "window_days": a.window_days, "results": rows, "asn_names": asn_names,
                   "evidence": acq.records}, f, indent=1)
    with open(os.path.join(case_dir, REGISTRY_NAME), "a") as reg:
        for p in (summ, man): reg.write(f"{sha256_file(p)}  {os.path.relpath(p, case_dir)}  (DERIVED)\n")
    say("\n".join(lines[6:6 + 2 + len(rows)]))
    say(f"\nevidence files: {len(acq.records)}  folder: {acq.run_dir}\nsummary: {summ}\nregistry: {os.path.join(case_dir, REGISTRY_NAME)}")

if __name__ == "__main__":
    try:
        main()
    finally:
        try:
            sys.stdout.flush()
        except (BrokenPipeError, OSError):
            os.dup2(os.open(os.devnull, os.O_WRONLY), sys.stdout.fileno())
