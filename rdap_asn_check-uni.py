#!/usr/bin/env python3
"""
rdap_asn_check.py — prefix-level ASN check (companion to rdap_batch.py)
INFRA-PATCH-MAPPING

rdap_batch.py answers: "what does the registry say about the ASN object?"
This script answers:   "what does the registry say about the SPACE the ASN announces?"
It reproduces, in one dated file, the manual curl steps recorded in the logs:

  1. RIPEstat announced-prefixes   (optionally date-matched with --at)
  2. RIPEstat asn-neighbours       (optionally date-matched with --at)
  3. ARIN RDAP ip/<prefix>         name, handle, registrant, arin_originas0_originautnums
  4. RIPEstat rpki-validation      per announced prefix (CURRENT state only; API has no time param)
  5. RIPEstat prefix-routing-consistency  per announced prefix (BGP vs whois/IRR view; replaces irr-routes, which does not exist)

Design rules (from the session record):
  - No hardcoded "expected" classification. Output is evidence, not a verdict.
  - Prefixes come from step 1, never typed by hand (no placeholders).
  - A non-ARIN prefix is flagged REGIONAL_PLACEHOLDER, not recorded as a finding.
  - arin_originas0_originautnums == [] is recorded but NOT discriminating
    (empty on flagged and control ASNs alike).
  - Every call's status/error is written to the file; a timeout is an INSTRUMENT
    result, not a routing event.

Usage:
    python3 rdap_asn_check.py --asn 11427
    python3 rdap_asn_check.py --asn 7046 --at 2026-05-05T00:00:00 --max-prefixes 40
    python3 rdap_asn_check.py --asn 7922 --hash-log SHADOW_MARKET_FILE_HASHES.txt
    python3 rdap_asn_check.py --asn 7046 --prefixes 192.0.2.0/24,2001:db8::/32

OPSEC: public read-only ARIN RDAP and RIPEstat only. Contact header matches rdap_batch.py.
"""

import argparse
import hashlib
import json
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

try:
    import requests
except ImportError:
    print("ERROR: requests not installed. Run: pip install requests")
    sys.exit(1)

HEADERS = {"User-Agent": "research/contact: lu@backwaterforensics.com",
           "Accept": "application/json"}
RIPESTAT = "https://stat.ripe.net/data/{ep}/data.json"
ARIN_IP = "https://rdap.arin.net/registry/ip/{res}"
DEFAULT_OUT_DIR = Path(__file__).parent / "output"


def get_json(url, params=None, timeout=20.0):
    """Return {'ok','status','data'|'error'}; never raises."""
    try:
        r = requests.get(url, params=params, headers=HEADERS, timeout=timeout)
        try:
            body = r.json()
        except ValueError:
            body = None
        if r.status_code >= 400:
            return {"ok": False, "status": r.status_code, "error": f"HTTP {r.status_code}", "data": body}
        return {"ok": True, "status": r.status_code, "data": body}
    except Exception as e:
        return {"ok": False, "status": None, "error": f"{type(e).__name__}: {e}", "data": None}


def ripestat(ep, **params):
    return get_json(RIPESTAT.format(ep=ep), params=params)


def classify_rdap(d):
    """Pull the fields the paper uses; flag non-ARIN placeholders."""
    if not isinstance(d, dict):
        return {"note": "NO_JSON"}
    name = d.get("name")
    handle = d.get("handle")
    ents = [(e.get("handle"), e.get("roles")) for e in d.get("entities", [])]
    notes = []
    if not name or d.get("port43", "").lower().find("arin") == -1:
        notes.append("REGIONAL_PLACEHOLDER? (heuristic: no name or port43 not ARIN) - verify at the owning RIR")
    return {
        "name": name,
        "handle": handle,
        "type": d.get("type"),
        "startAddress": d.get("startAddress"),
        "endAddress": d.get("endAddress"),
        "port43": d.get("port43"),
        "originas": d.get("arin_originas0_originautnums"),
        "entities": ents,
        "notes": notes,
    }


def main():
    ap = argparse.ArgumentParser(description="Prefix-level ASN check — INFRA-PATCH-MAPPING")
    ap.add_argument("--asn", required=True, help="ASN, digits only (e.g. 11427)")
    ap.add_argument("--at", help="UTC time for announced-prefixes/asn-neighbours, e.g. 2026-05-05T00:00:00")
    ap.add_argument("--prefixes", help="comma-separated explicit prefixes (skips step 1 discovery for steps 3-5)")
    ap.add_argument("--max-prefixes", type=int, default=25, help="cap on prefixes sent to steps 3-5 (default 25)")
    ap.add_argument("--filter", help="only query prefixes starting with this text, e.g. 156. (applied before the cap)")
    ap.add_argument("--delay", type=float, default=1.5, help="seconds between calls")
    ap.add_argument("--out", help="output path (default output/AS<asn>-prefixcheck-<UTC>.txt)")
    ap.add_argument("--hash-log", help="append 'shasum -a 256' style line to this file on completion")
    args = ap.parse_args()

    if not args.asn.isdigit():
        print("ERROR: --asn must be digits only")
        return 2
    asn = args.asn
    ts = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    DEFAULT_OUT_DIR.mkdir(parents=True, exist_ok=True)
    outpath = Path(args.out) if args.out else DEFAULT_OUT_DIR / f"AS{asn}-prefixcheck-{ts}.txt"

    lines = []

    def emit(s=""):
        print(s)
        lines.append(s)

    def block(title):
        emit("\n" + "=" * 80)
        emit(title)
        emit("=" * 80)

    def raw(res):
        emit(f"  status={res.get('status')} ok={res['ok']}" + (f" error={res.get('error')}" if not res["ok"] else ""))
        emit("  [RAW JSON]")
        emit(json.dumps(res.get("data"), indent=2))

    emit("=" * 80)
    emit(f"PREFIX-LEVEL ASN CHECK | AS{asn} | run {ts} UTC | TLP:AMBER+STRICT")
    emit(f"Date-match (--at): {args.at or 'NONE (current state)'}")
    emit("Note: rpki-validation and prefix-routing-consistency report CURRENT state regardless of --at.")
    emit("=" * 80)

    # Step 1 — announced prefixes
    block(f"STEP 1 — RIPEstat announced-prefixes AS{asn}")
    p = {"resource": f"AS{asn}"}
    if args.at:
        p["starttime"] = args.at
        p["endtime"] = args.at
    r1 = ripestat("announced-prefixes", **p)
    prefixes = []
    if r1["ok"] and r1["data"]:
        prefixes = [x["prefix"] for x in r1["data"].get("data", {}).get("prefixes", [])]
    emit(f"  prefixes returned: {len(prefixes)}")
    raw(r1)
    time.sleep(args.delay)

    # Step 2 — neighbours
    block(f"STEP 2 — RIPEstat asn-neighbours AS{asn}")
    p = {"resource": f"AS{asn}"}
    if args.at:
        p["query_time"] = args.at
    r2 = ripestat("asn-neighbours", **p)
    raw(r2)
    time.sleep(args.delay)

    targets = [x.strip() for x in args.prefixes.split(",")] if args.prefixes else prefixes
    if args.filter:
        targets = [t for t in targets if t.startswith(args.filter)]
        emit(f"\n  FILTER --filter {args.filter!r}: {len(targets)} prefixes match.")
    if len(targets) > args.max_prefixes:
        emit(f"\n  NOTE: {len(targets)} prefixes; steps 3-5 capped at {args.max_prefixes} (--max-prefixes). "
             f"Remaining {len(targets) - args.max_prefixes} NOT queried.")
        targets = targets[: args.max_prefixes]

    # Steps 3-5 per prefix
    for i, pfx in enumerate(targets, 1):
        block(f"PREFIX {i}/{len(targets)} — {pfx}")

        emit("\n-- STEP 3: ARIN RDAP ip --")
        # query by the network address of the prefix
        r3 = get_json(ARIN_IP.format(res=pfx.split("/")[0]))
        summary = classify_rdap(r3.get("data")) if r3["ok"] else {"note": r3.get("error")}
        emit("  SUMMARY: " + json.dumps(summary))
        raw(r3)
        time.sleep(args.delay)

        emit("\n-- STEP 4: RIPEstat rpki-validation --")
        r4 = ripestat("rpki-validation", resource=f"AS{asn}", prefix=pfx)
        state = None
        if r4["ok"] and r4["data"]:
            state = r4["data"].get("data", {}).get("status")
        emit(f"  RPKI status: {state}")
        raw(r4)
        time.sleep(args.delay)

        emit("\n-- STEP 5: RIPEstat prefix-routing-consistency (unverified until first live run) --")
        r5 = ripestat("prefix-routing-consistency", resource=pfx)
        raw(r5)
        time.sleep(args.delay)

    emit("\n" + "=" * 80)
    emit(f"END | AS{asn} | {len(targets)} prefixes processed | {outpath.name}")
    emit("Instrument results (timeouts, 4xx/5xx) are NOT routing events.")
    emit("=" * 80)

    outpath.write_text("\n".join(lines) + "\n")
    digest = hashlib.sha256(outpath.read_bytes()).hexdigest()
    hashline = f"{digest}  {outpath.name}"
    print("\nSHA-256: " + hashline)
    if args.hash_log:
        with open(args.hash_log, "a") as h:
            h.write(hashline + "\n")
        print(f"Appended to {args.hash_log}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
