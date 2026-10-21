# How Unassigned Addressing Created a New Attack Vector: An Analysis of Dormant Autonomous System Exploitation in Backbone Internet Infrastructure

**Backwater Forensics | Lu Anne Gammage (Esposito), MS Digital Forensic Science | Revised 2026-10-20**

**Status:** Final revision following round-1 peer review. Supersedes the public version dated 2026-08-25.

---

## 1. Executive Summary

Autonomous System (AS) numbers that go dormant after a carrier acquisition, bankruptcy, or internal retirement are conventionally treated as administrative debris — bookkeeping left uncorrected, not a security concern. This paper argues that treatment is wrong for a specific, testable reason: dormant ASN space with no accountable current operator is address space with no one positioned to notice or contest unauthorized use of it, and that gap is not merely untidy, it is exploitable. This is not a novel theoretical claim; the technique is independently documented in prior academic research (Testart et al., 2019; Nemmi et al., 2021) and by network-security researchers tracking real-world cases (Guilmette, 2018; Madory, 2018). This paper's contribution is a sustained, case-study-depth investigation of the pattern operating against real backbone infrastructure, built on a six-year arc from on-the-ground observations to a confirmed, evidence-graded finding set.

**Methodology.** The investigation applies a null-hypothesis-first standard throughout: any candidate ASN is presumed to reflect ordinary post-acquisition administrative lag until the evidence clears a specific bar (Section 2.4, Section 3). That bar is a five-tier confidence framework (Inferred, Digital Recon Affirmed, Remote Forensic Confirmed, Ground Conditions Confirmed, Active Exploit Confirmed) and a three-part digital validation pipeline — passive DNS fingerprinting, RDAP registrant and allocation checks, and BGP routing/upstream analysis — with confirmation requiring at least one validation level to independently clear its own evidentiary standard.

**Findings.** Applied to a 24-ASN evidence base, this standard cleared eight candidates against the null hypothesis for the two that rejected it — a null hypothesis doing real analytical work rather than functioning as a formality (Section 4.2). The thesis predicts a specific cross-ASN signature: the same non-carrier secondary-market sub-allocator (Cloud Innovation Ltd / LARUS-SERVICE-MNT) appearing in the dormant space of otherwise-unrelated carrier ASNs. That signature is confirmed in one ASN, AS11427 (Charter/TWC lineage), and supported by an unverified lead in a second, AS7029 (Windstream lineage), pending a block-level registry check (Section 4.1). A separate ASN, AS7046, was investigated as a candidate third-party-control finding and did not clear that bar on further evidence — its upstream relationships confirm normal, active Verizon operation, consistent with its RFC 2270 customer-aggregation registration. A malicious domain was found resolving into its address space regardless, discovered through this investigation's own hunting methodology rather than the ASN-anomaly question, which this paper reports as an impact finding (Section 5.3) rather than a stewardship-gap finding.

**Impact.** For end users, the consequence of this structural gap is not abstract: inherited IP reputation from unrelated prior tenants, and routing paths through international infrastructure inconsistent with a domestic subscriber's reasonable expectations. Separately, and independent of the stewardship-gap thesis, a malicious domain was found resolving into actively-operated carrier customer space (Section 5.3) — evidence that this kind of exposure is not limited to dormant or unstewarded ASNs. In the documented stewardship-gap cases, the structural cause is consistent: no party is accountable for the space, so no clear remediation path exists when something goes wrong.

**Contribution and open question.** This paper's findings independently corroborate a pattern separately identified in academic literature (Testart et al., 2019; Nemmi et al., 2021; NIST, 2019) located only after this investigation's methodology and empirical work were substantially complete (Section 2.2) — convergent validity from two unrelated efforts, not a study designed around prior work. A question this paper's own review process surfaced, and does not yet have data to answer: when a routing anomaly is investigated at a distance, how often does what looks like a real event turn out to be a monitoring-instrument artifact rather than a genuine change in the network? Section 4.4 documents one case where this distinction mattered directly.

---

## 2. Thesis and Principles of the Research

### 2.1 Origin of the Inquiry

This investigation began as a set of on-the-ground and online observations directed at specific subjects and locations. Those early observations are not themselves evidence for the argument this paper makes — per this project's evidentiary standard, physical and single-source observations are discovery triggers, not findings — but they are the reason a backbone-infrastructure investigation was opened at all. The zoom-in they prompted led to a broader question: was the routing behavior observed around those cases idiosyncratic to those targets, or was it an instance of a general, repeatable condition in how the internet's backbone handles address space that carriers have stopped actively managing?

Over six years, that question narrowed from "something is wrong with this specific routing" to a testable, general claim about a structural property of Autonomous System (AS) allocation and BGP routing: that unassigned, dormant, or administratively orphaned address space is not merely untidy bookkeeping, but a distinct and exploitable attack surface.

### 2.2 Thesis

**Dormant and unassigned Autonomous System space constitutes a persistent, exploitable attack vector in backbone internet infrastructure — separate from and not fully explained by ordinary post-acquisition administrative lag — because the absence of active stewardship removes the one control (an attentive registrant) that would otherwise detect and contest unauthorized routing.**

This is not a novel theoretical claim in isolation. It is independently documented in the academic literature: Nemmi et al. (2021) identify dormant ASNs "suddenly waking up" to hijack address space, citing AS10512 — allocated for 17 years, active in BGP for only 31 days, during which it hijacked 60 /16 prefixes including space belonging to Spectrum (AS11426). Testart et al. (2019) trained a classifier that flagged 934 ASes with behavioral similarity to known serial hijackers. NIST SP 800-189 formally names both "announcement of unallocated address space" and "prefix squatting" as interdomain routing attack patterns. This paper's contribution is not to establish that the technique exists — the literature already does that — but to document its operation, at case-study depth, against real backbone infrastructure over a sustained investigation, and to test for a specific repeatable signature: the same non-carrier secondary-market sub-allocator appearing across multiple, otherwise-unrelated dormant carrier ASNs.

**A note on chronology, stated plainly for methodological honesty.** This investigation's methodology, hypothesis, and the confirmed findings reported in Section 4 were developed and largely completed before this academic literature was located. The literature above was found during the drafting of this paper — after the empirical work, not before it — and its role here is independent corroboration that this project's findings match a pattern separately documented by academic researchers using different methods and a different dataset, not a framework this investigation was designed against. That distinction matters: a finding that happens to match prior literature discovered afterward is evidence of convergent validity, not evidence that the investigation was built to reproduce a known result. The remainder of this paper is written to keep that distinction clear — the literature is cited as corroboration, never as a source the methodology was derived from.

### 2.3 What This Paper Is Not Arguing

Per the Designation Gate applied throughout this project's methodology, no actor or entity is named as culpable in this paper unless the evidentiary bar for that claim is independently cleared and documented. This paper describes **infrastructure conditions** — what address space is being announced, by what AS, with what (or absent) registration authority — not intent, and not attribution to a named actor beyond what ARIN/RDAP records establish as a matter of public record. Where a carrier's own ASN shows an anomaly (e.g., Charter appearing under three different status classifications across its ASN portfolio), the paper's default explanation is administrative lag until the evidence clears the higher bar described in Section 2.4.

### 2.4 The Null Hypothesis This Paper Had to Clear

Large carriers accumulate ASNs through decades of acquisition (TCI → AT&T Broadband → Comcast; Time Warner Cable → Charter; MCI → Worldcom → Verizon Business; Global Crossing → Level 3 → Lumen). A dormant or inconsistently-documented ASN is the expected byproduct of that history, and by itself proves nothing. The working null hypothesis throughout this investigation has been:

> **H0 — Administrative Lag:** Apparent routing anomalies in legacy carrier ASNs are fully explained by ordinary post-acquisition record-keeping delay. No unauthorized third party is routing the space; the registrant's own network engineering has simply not caught up to ARIN's records, or vice versa.

H0 is the default explanation for any single anomalous observation in this dataset. It is only set aside for a given ASN when the evidence clears one of the Tier R (Remote Forensic Confirmed) confirmation standards described in Section 3 — not on the basis of the anomaly's appearance alone. Section 4.2 and the corresponding Section 8.1b entry document a worked example (AS10913) of a finding that was tested against H0, found to be H0 after all, and retracted — which the project methodology treats as the process working correctly, not as an error to be minimized.

### 2.5 Guiding Principles

The research adheres to the following principles, carried consistently across all evidence collection, characterization, and disclosure activity described in Section 3–5:

| Principle | Application |
|---|---|
| **Actor-agnostic framing** | Findings describe infrastructure conditions ("AS11427 announces prefixes it has no recorded authorization for"), not actors or motive. |
| **Evidence-graded claims** | Every finding is traceable to a named source, database query, or documented OSINT method, and carries an explicit confidence tier (Section 3.2). |
| **Reproducibility** | Methodology is public-tool-based (ARIN RDAP, RIPEstat, Robtex) and explicit enough that an independent researcher with the same access could reach the same findings. |
| **Partner-oriented disclosure** | Carriers and CISA are treated as partners in remediation, not subjects of accusation. Disclosures give carriers a remediation window rather than asserting wrongdoing. |
| **Null-hypothesis-first** | The benign/administrative explanation is stated and evaluated before any anomaly label is applied (Designation Gate). |
| **Cleared findings are retained** | A finding that does not hold up (e.g., AS10913, Section 2.4) is documented as a retraction, not deleted — clearing a lead is treated as evidentiary output in its own right. |

---

## 3. Experiment Structure, Hypothesis, and Methodology

### 3.1 Formal Hypotheses

**H1 (working hypothesis):** A measurable subset of dormant or under-stewarded Autonomous System space is being used to route address blocks without documented authorization from the registrant, and this activity follows a repeatable pattern rather than occurring as isolated, unrelated incidents.

**H0 (null hypothesis):** Observed anomalies in legacy carrier ASN routing are attributable to ordinary administrative lag following corporate acquisition, with no unauthorized third-party routing activity present.

**H1 is accepted for a given ASN only when at least one Tier R confirmation standard (Section 3.4) is independently met.** Meeting a lower evidentiary tier (Inferred or Digital Recon Affirmed) is not sufficient to reject H0 for that ASN; it moves the item to the validation queue rather than to a confirmed finding.

### 3.2 Confidence Tier Framework

All findings in this investigation are graded against a five-tier confidence scale, applied consistently from initial discovery through final characterization:

| Tier | Code | Meaning |
|---|---|---|
| Inferred | I | Acquisition history predicts a seam condition — not directly observed |
| Digital Recon Affirmed | D | Passive OSINT confirms conditions favorable to the hypothesis |
| Remote Forensic Confirmed | R | PCAP, live BGP behavior, passive DNS, or ARIN/RDAP verification — forensic-grade digital evidence |
| Ground Conditions Confirmed | G | Physical or case-overlap corroboration — not used as a confirmation pathway in this investigation (Section 3.2); listed for completeness against the parent framework |
| Active Exploit Confirmed | A | Direct, first-hand confirmation of active exploitation — victim report, ISP action, or law enforcement action — analyst-assigned only, never automated |

This paper applies four of the five Backwater Forensics confidence tiers (I, D, R, A). Ground Conditions Confirmed (G) is part of the parent framework but was not a confirmation pathway used in this investigation. No backbone/ASN finding in this paper reached Tier A; an earlier Tier A assignment for AS7015 was corrected to Tier R (Section 8.1b). Tier A is defined above for completeness.

This paper reports findings at Tier R or above only, consistent with the confirmation standard described below. Lower-tier items (I, D) are described in Section 4 as candidates under monitoring, not as confirmed findings.

### 3.3 Validation Pipeline

The investigation proceeds through a phased pipeline, moving a candidate ASN from initial discovery to a confirmed disposition:

- **Phase A** — Initial validation via RIPE/ARIN RDAP lookup (registrant identity, allocation date, basic routing presence). Corresponds to Validation Levels 1–2 below.
- **Phase B** — Digital risk assessment (prefix count, pDNS presence, upstream transit relationships). Overlaps the start of Level 3.
- **Phase C** — PTR / routing validation (confirmation-grade checks described in 3.4 below). Corresponds to Validation Levels 3–5.

A candidate ASN is not reported as confirmed until it has passed through Phase C and cleared at least one Tier R standard. Validation Levels 1–2 (Phase A's registrant-identity and allocation-date lookups) are not independently sufficient to confirm anything — they establish the candidate pool, not a finding — which is why only Levels 3–5 are given full confirmation standards in Section 3.4. No finding in this paper is reported at Level 1 or 2 alone.

### 3.4 Tier R Confirmation Standards (Validation Levels 3–5)

*Note on terminology: "Validation Level" (below) refers to which diagnostic test was run in the validation pipeline. It is a separate axis from the confidence tiers (I, D, R, A) defined in Section 3.2 — a finding can pass Validation Level 4 (RDAP) and still only carry Tier R confidence until further corroborated. The two are related but not interchangeable.*

Three independent diagnostic tests are available to move an ASN from `PENDING_VERIFICATION` to a confirmed status. Any single test meeting its confirmation standard is sufficient to confirm at Tier R; all three meeting standard together constitutes the strongest evidentiary basis.

**Level 3 — Passive DNS Fingerprint.** Tests whether the ASN's announced IP space resolves to live carrier infrastructure hostnames, dormant space, or anomalous/foreign hostnames inconsistent with the ASN's documented carrier history. Confirmed when carrier-infrastructure hostnames resolve from space the ASN has no documented right to announce, or when foreign/anomalous hostnames resolve from ostensibly domestic carrier space. Tooling: `asn_pdns_puller.py` against RIPEstat (prefix enumeration) and Robtex (passive DNS), no authentication required.

**Level 4 — RDAP Registrant and Allocation Check.** Tests whether the registry record for an announced block is consistent with the ASN announcing it. Confirmed when the registrant of record is a non-carrier entity with no documented acquisition chain to the announcing ASN, or when the announced space is registry-held with no end-user allocation on record at the responsible registry. The optional `originas` field is recorded as a supporting observation only; it is not an authorization record (RPKI ROAs and IRR route objects are), and the control comparison below shows it does not discriminate. Where ARIN returns a referral placeholder naming another regional registry, the block is re-queried at that registry before any conclusion is drawn. Data sources: ARIN RDAP and the responsible regional registry's RDAP (public, read-only).

*Control-comparison result (2026-08-27).* A direct check of AS7922 (Comcast's own production ASN, never flagged as anomalous, this paper's own CLEAN baseline throughout) found the identical `originas: []` state on every IPv6 block sampled — `COMCAST6NET`, `CIMQAV6`, and `ALBUQUERQUE-CBC-V6-1` (3 control blocks, against 6 flagged-ASN blocks). Combined with every prior check of the ASNs this paper does flag (AS7046's WIRE-V6, TERRENAP-V6, CFTC-NETWORK, and DOLNET; AS11427's `RRSW-V6` and `RRWE-IPV6`), the `originas` field is empty in 100% of blocks checked across both the flagged and control sets, with no variance observed on any date. This confirms directly what Section 4.3 and 8.1b already argue on other grounds: an empty `originas` field is not, on its own, a discriminating signal — it appears to be the default administrative state for IPv6 space across large carrier and hyperscale networks generally, flagged or not. This paper does not treat `originas: []` as independently dispositive anywhere it remains the only Level 4 evidence for a claim; where it is cited (Section 8.1b), it is one supporting data point among several, never the sole basis for a finding.

**Level 5 — BGP Prefix and Routing Analysis.** Tests whether current announced prefix composition and upstream transit relationships are consistent with the ASN's documented history. Confirmed when international backbone upstreams appear for a domestic-only carrier ASN with no documented international operations, when prefix composition includes geographically inconsistent space, or when two independently dormant ASNs share an identical upstream set (indicating common operational control rather than coincidence). Data source: RIPEstat (public, read-only). A secondary, non-dispositive check cross-references the RIPE Internet Routing Registry (IRR) for a registered routing policy; absence of one is a supporting flag, not independent confirmation.

### 3.5 Sampling Frame

The candidate population was seeded from a set of geographic nodes (ZIP-code-based) associated with the six-year investigation's original discovery triggers, subsequently expanded to include university-network nodes as a comparison subset. ZIP-code seeding is used strictly as a sampling method to identify which carrier ASNs serve a given locality for further RDAP/BGP analysis — it is not itself evidentiary, and no physical-location finding is reported in this paper's scope (Autonomous System routing conditions only, per project scope decision).

The sampling frame grew across three points in the investigation rather than being fixed from the outset. The 2026-05-05 baseline register comprised 19 ASNs, spanning legacy TCI/AT&T Broadband, Adelphia/Insight, Time Warner Cable/Charter, MCI/Worldcom, Global Crossing/Level 3, EarthLink/Internap, and Windstream lineages — chosen because each represents a distinct acquisition chain with a plausible dormancy or stewardship gap. That register grew to 20 shortly after (AS5650 added), then to 23 ASNs through the registry expansion documented in Section 8.3 (`BACKBONE-INVESTIGATION-LOG-v2.md`, entry I-027, states this step explicitly as "20→23 ASNs"), and to the paper's full 24-ASN evidence base with the later addition of AS7046, which entered the investigation through a separate monitoring thread opened 2026-05-19 (research log I-032), whose dark-window premise was later retracted (Section 4.4), rather than the original acquisition-lineage sampling logic above. The bybanking.com finding came afterward, from the first passive-DNS run against AS7046 on 2026-06-16 (I-047; Sections 4.3, 5.3). The count reported elsewhere in this paper (Executive Summary, Sections 4.0, 4.2, and 8) is this final, fully reconciled 24.

### 3.6 Corroboration Threshold

A three-independent-hit threshold applies to cyber/network evidence: three independent cyber/network findings (e.g., pDNS anomaly + RDAP gap + shared upstream with another anomalous ASN) confirm a pattern as deliberate rather than coincidental, where a single hit alone would not. This threshold applies only to cyber/network evidence; it does not apply to and is not satisfied by physical/on-the-ground observations, which are excluded from this paper's evidentiary base by design (Section 3.5).

**Which standard governs which claim.** Section 3.4's single-Level sufficiency rule and this section's three-hit rule answer different questions and should not be read as interchangeable. A single Level 3–5 confirmation is sufficient to reject H0 and report a Tier R *anomaly* — that a given ASN's routing is inconsistent with its documented history. It is not, on its own, sufficient to characterize that anomaly as *deliberate exploitation* rather than a possible coincidence; that stronger characterization requires this section's three-independent-hit threshold. Where this paper uses exploitation-implying language (e.g., Section 4.1's cross-ASN signature) after fewer than three independent hits, that language should be read as describing the confirmed anomaly, not an independently established claim of deliberateness.

### 3.7 Data Sources

| Source | Role | Access |
|---|---|---|
| ARIN RDAP | Registrant identity, allocation history, originas authorization | Public, read-only |
| RIPEstat | Announced prefixes, routing status, ASN upstream neighbors | Public, read-only |
| Robtex | Passive DNS | Public, read-only |
| RIPE IRR | Routing policy registration (secondary flag) | Public, read-only |
| CISA supplemental filings | Disclosure and correction record for filed findings | Internal case record |
| Malware sandboxes (Falcon Sandbox / Hybrid Analysis) | **Validation only** — DNS resolution observations | Public reports; analyst-submitted runs |

**Sandbox data as validation.** Sandbox output is not a primary evidence stream in this paper. A sandbox measures how a domain responds to being executed in an analysis environment, and repeated submissions can shape what is observed. It is used in one way only: its DNS resolution observations (which address a domain resolved to, and with what TTL, at the time of a run) validate a pattern first established by Level 3–5 evidence. Sandbox verdicts, threat scores and behavioral output are not relied on for any claim.

### 3.8 Methodological Limitation Acknowledged in the Literature

Academic literature located after this investigation's methodology was developed (see the chronology note in Section 2.2) independently corroborates a limitation this project encountered directly: BGP-activity analysis alone cannot fully distinguish malicious squatting from other causes without administrative allocation context. Nemmi et al. (2021) note that some dormant-ASN awakenings (e.g., 31 ASNs reactivating simultaneously in April–July 2020) were only confirmable as malicious by cross-referencing known-malicious upstream ASNs, not from prefix behavior in isolation. This investigation's combination of RDAP registrant/allocation checks and BGP upstream analysis (Section 3.4, Validation Levels 4 and 5) was designed independently and happens to address the same limitation.

---

## 4. Findings

### 4.0 Overview

Findings are organized thematically rather than ASN-by-ASN, consistent with the thesis in Section 2: the paper's contribution is the *pattern*, not any single ASN's status. Full per-ASN evidence, dates, and file references are in Section 8. This section draws on that evidence base to make three arguments in sequence: what the data show for the cross-ASN signature predicted in Section 2.2 (one confirmed instance, one pending lead); that the null-hypothesis discipline in Section 2.4 actually separated administrative lag from anomaly rather than assuming the answer; and that a candidate third-party-control finding (AS7046) was investigated and, on further evidence, did not hold up — retained here as an example of the discipline working, not deleted, per Section 2.5.

### 4.1 The Cross-ASN Signature: One Confirmed Instance, One Pending Lead

Section 2.2 proposed a specific, falsifiable signature distinguishing systematic exploitation from ordinary administrative lag: the same non-carrier secondary-market sub-allocator appearing across multiple, otherwise-unrelated dormant carrier ASNs. That signature is confirmed in one instance and supported by a second, pending independent verification.

AS11427 (TWC-11427-TEXAS, Charter's own ARIN registration, BGP routing authority unknown) carries a prefix composition of 21% legacy Time Warner Cable space, 77% Cloud Innovation Ltd (Seychelles, AFRINIC secondary-market registrant ORG-CIL1-AFRINIC), and 2% APNIC space under MAINT-SNPL-PK (Pakistan). A subset of that space — the 156.x.x.x range — is ERX space now administered by AFRINIC. The ARIN record on file (`whois_arin_156x_AS11427_20260505.txt`) is ARIN's referral for ERX space and cannot by itself show whether an end-user allocation exists; that is answered only by AFRINIC's own record, queued with the IRR/RPKI check on the same blocks (Section 8.1b). AS11427's Level 4 confirmation rests on the registrant prong — Cloud Innovation Ltd, a non-carrier registrant with no acquisition chain to Charter/TWC — not on the `originas` field (Section 3.4).

AS7029 (Windstream, WINDSTREAM_RECLAIM status following its own reclaim confirmation) is separately associated with a 154.194.16.0/21 block registered to Future Tech Distribution under the same sub-allocator, LARUS-SERVICE-MNT — an association documented in this project's correction log but not yet independently confirmed by a block-level RDAP query (Section 8.1b); treated here as a supporting data point pending that confirmation, not as an independently verified second instance of the signature. A RIPEstat check recorded in this project's research log (I-071; dated rerun I-072, 2026-08-17) found `154.194.16.0/21` **not** among AS7029's announced prefixes; five other 154.x.x.x /24s were announced (`154.6.228.0/24`, `154.6.229.0/24`, `154.6.230.0/24`, `154.16.13.0/24`, `154.30.152.0/24`), registrants not yet checked. Whether the /21 was announced by AS7029 at the time of the original correction-log entry is not established by any dated record on file.

One carrier ASN — AS11427 — carries a confirmed, RDAP-verified instance of address space from a Seychelles LIR (Cloud Innovation Ltd / LARUS-SERVICE-MNT) routed through its dormant allocation, with no acquisition-history explanation connecting that LIR to Charter/TWC. AS7029's association with the same sub-allocator is documented in this project's own correction log but rests on a source that has not yet been independently confirmed by a block-level RDAP query (see the note above and Section 8.1b); it is reported here as a lead consistent with the same pattern, not as a second confirmed instance. If independently confirmed, the two together would represent unrelated carrier ASNs — unrelated acquisition histories (Charter/TWC vs. Windstream), unrelated geographies, unrelated original owners — carrying address space from the same external sub-allocator, which post-acquisition record-keeping delay alone would not explain. Until that confirmation exists, this paper's falsifiable claim rests on the single verified AS11427 instance; the AS7029 lead is disclosed for transparency and flagged for the next validation pass, not treated as established. This finding is consistent with, and — pending AS7029's confirmation — would add a case instance to, the "systematic routing vehicle" pattern documented by Nemmi et al. (2021) in dormant-ASN hijacking generally.

### 4.2 The Null Hypothesis Did Real Work

A methodology that never clears H0 for anything is not rigorous — it is unfalsifiable. Table 4.1 shows the null hypothesis was applied evenhandedly across the 24-ASN evidence base (Section 8): eight candidates were cleared against it and two rejected it. Of the remaining fourteen, one is a lead not yet dispositioned (AS7029), two are status corrections made during drafting (AS33363, AS54396), and eleven are baseline, comparison, or control entries (Section 8.1c).

**Table 4.1**
*Disposition of Candidate ASNs Against the Administrative-Lag Null Hypothesis*

| Disposition | ASNs | Basis |
|---|---|---|
| **H0 held — cleared as administrative lag / misattribution** | AS10913, AS6181, AS2686, AS5650, AS11426, AS6128, AS8069 | Direct RDAP registrant confirmation contradicted the working hypothesis in each case (Section 8: AS10913 retraction, CISA CORRECTION-002; AS6181 Cincinnati Bell/FUSE-NET, corrected pre-disclosure; AS2686/AS5650 confirmed legitimate current operators via RDAP + RIPEstat). AS11426/AS6128 (moved here 2026-08-25): a carrier retaining a second, redundant legacy ASN with RDAP-confirmed continuity cites no Level 3–5 hit, so it does not reject H0. **AS8069: MISATTRIBUTION was this investigation's own working determination as early as 2026-05-08 — an early "OWNERSHIP_ANOMALY" working label, applied 2026-05-05 before ARIN's block registration was checked the following day, was never updated after that check confirmed continuous Microsoft ownership since 1997 with no Ameritech connection anywhere in the record.** Independently re-confirmed 2026-08-27 with fresh ARIN and RIPE routing checks (see 8.1c) |
| **H0 held — investigated as candidate third-party control, confirmed normally operated** | AS7046 | Registered `RFC2270-UUNET-CUSTOMER`; upstream peer data confirms active Verizon operation (three of five upstream peers are Verizon Business/MCICS-registered sibling ASNs; see 4.3 and 8.1b). A malicious domain was found in its address space regardless, via this investigation's own validation testing — reported as an impact finding (Section 5.3), not as evidence this ASN is unstewarded |
| **H0 rejected — Tier R anomaly, inconsistent with documented history** | AS11427, AS7015 | Cleared the Tier R confirmation standard (Section 3.4). **AS11427:** Level 4 registrant prong (non-carrier AFRINIC secondary-market registrant, Section 4.1) and Level 5 prefix composition. **AS7015:** Level 5 routing/upstream inconsistency and international registry records at the 2026-05-05 baseline (Section 8.1b); its international-upstream criterion has not yet been compared against the control ASNs, and that check is queued. `originas` gaps are not counted toward either (Section 3.4). Per Section 3.6, "anomaly" here does not by itself establish deliberate exploitation |
| **Lead — not yet dispositioned** | AS7029 | WINDSTREAM_RECLAIM. LARUS-SERVICE-MNT association on `154.194.16.0/21` documented only in this project's correction log; the /21 was not among AS7029's announced prefixes at a 2026-08-17 check (I-072). Pending a block-level AFRINIC RDAP query on the /21 and registrant checks on five announced 154.x.x.x /24s (Sections 4.1, 8.1b). Counted as neither held nor rejected |
| **Resolved during drafting — corrected, not left pending** | AS33363 (→ RETENTION_ANOMALY), AS54396 (→ MISATTRIBUTION) | Register cross-check (`ZOMBIE-ASN-REGISTRY.db`) caught two stale statuses in this paper's own earlier draft — see Section 8 entries. AS33363's retention status cites no Level 3–5 hit (same basis as AS11426/AS6128) and is not counted as an H0 rejection; its 2026-07-15 prefix decline (494→436) is logged as an open change, not a finding |

Two of the paper's clearances — AS10913 and AS6181 — are worth naming specifically because they show the discipline catching itself at different points in the disclosure pipeline. AS10913 was filed to CISA as a confirmed zombie on 2026-05-02 and retracted three days later (CORRECTION-002) — the correction happened, but only after external disclosure. AS6181 was headed for the same filing, built on a full write-up (geography, upstream peers, a 14-year "double migration failure" narrative) — and was caught and corrected internally before it ever reached CISA or FBI. Methodologically these are the same discipline; operationally, the second is the better outcome, since it demonstrates the check working *before* an error reaches an external partner rather than after.

The mirror-image case is arguably the more important one: AS11427 — this paper's central, fully-confirmed instance — was initially filed CLEAN at Phase A, and only reclassified THIRD_PARTY_CONTROL after external disclosure (CISA CORRECTION-001, Section 8.1b). A false negative caught late carries more risk than a false positive caught late: a false positive wastes a partner's attention, while a false negative lets something real go unflagged for longer. That this correction happened at all, and is documented rather than smoothed over, is consistent with the same "cleared findings are retained" discipline (Section 2.5) — applied here in the direction that matters most.

### 4.3 AS7046 — Investigated as a Candidate Finding, Redirected on Further Evidence

An earlier draft of this paper treated AS7046 as a third-party-control finding parallel to AS11427 and AS7015 — dormant, unstewarded federal address space, occupied by unrelated malicious infrastructure. On round-1 peer review and a subsequent evidence recheck (2026-08-25), that framing did not hold up, and per the "cleared findings are retained" principle (Section 2.5), the retraction is documented here rather than the section simply disappearing.

Two things changed the assessment. First, AS7046's registration (`RFC2270-UUNET-CUSTOMER`) describes a specific, ordinary function — a shared ASN a provider uses to originate its single-homed customers' address blocks — under which continuous, fully-visible routing is the *expected* state, not evidence of a stewardship gap. Second, and more directly: a fresh RIPEstat upstream-neighbor query (2026-08-25) found that three of AS7046's five upstream peers are themselves Verizon Business/MCICS-registered sibling ASNs, and the dominant relationship by a wide margin is AS701 — Verizon's own UUNET backbone (Section 8.1b). That is not consistent with third-party or unauthorized control; it is what a normally-operated carrier customer-aggregation ASN's upstream table looks like.

A malicious domain was found resolving into AS7046's address space regardless of this reclassification — discovered through this investigation's own validation testing, not dependent on AS7046 being dormant — and is retained and reported in full as an impact finding (Section 5.3), not as evidence for this paper's stewardship-gap thesis.

Worth stating plainly, since it is a separate claim from AS7046's own disposition: the fact that this reclassification happened does not undermine the value of the hunting step that led to the discovery. AS7046 entered the validation pipeline as a flagged candidate — flagged, in hindsight, on a premise later retracted (Section 4.4) — and that flag is what triggered the Level 3 passive-DNS check that found the domain. Whether the flag's underlying cause turned out to be third-party control (as with AS11427) or a benign administrative characteristic (as here) is a separate question from whether running the hunting step on a flagged candidate is a productive method — this case demonstrates that it is, independent of how the ASN-level question resolved. A methodology that only produces usable results when its initiating hypothesis is confirmed is a narrower, weaker claim than one that produces usable results even when the hypothesis is not. The hunting method and the full trace are documented in Appendix A.

### 4.4 A Monitoring-Instrument Artifact, Caught and Corrected

An earlier draft of this paper reported that AS7015 and AS7046 went dark around 2026-05-19. On round-1 peer review, that claim was rechecked directly against the analyst's own contemporaneous monitoring records rather than against the paper's later summary of them — and it did not hold up.

For AS7015: the analyst's own working notes from 2026-05-22, written the same week and before any "dark window" framing existed, state plainly that AS7015's prefix count was "stable at 121 (timeout streak cleared — **NOT going dark**; status: ZOMBIE_TRANSIT restored)." What actually occurred was a series of RIPEstat query timeouts, compounded by a documented, multi-day automated-monitoring failure (`MONITOR FAILURE — sandbox 403`, a network-proxy refusal in the monitoring environment, unrelated to malware sandboxes) affecting the pipeline broadly — including AS7922, a CLEAN control ASN, on the same dates. When a manual query finally succeeded, AS7015's count matched its pre-window baseline exactly. This is not consistent with a real routing withdrawal; it is consistent with the monitoring instrument failing and then recovering. AS7015's Tier R finding (routing/upstream inconsistency identified at the 2026-05-05 baseline; see Section 3.4 on `originas`) is unaffected by this correction and stands on its own evidentiary basis — see Section 8.1b. What is retracted is only the later dark-window claim.

For AS7046: this investigation's monitoring of the ASN began on 2026-05-19 — meaning there is no prior baseline against which a "went dark" transition could have been observed. The claim described an assumed transition, not an observed one. Combined with Section 4.3's finding that AS7046 is a normally, continuously operated ASN, no disruption claim is made for it in this paper.

No dark-window claim is made in this revision for either ASN. This section is retained, per Section 2.5's "cleared findings are retained" principle, specifically so the correction is visible rather than the section quietly disappearing.

---

## 5. Impact to Users

### 5.0 Overview

The findings in Section 4 describe an infrastructure condition. This section describes what that condition means for the people whose traffic passes through it — subscribers who have no visibility into which ASN carries their packets, no way to know whether that ASN has an accountable current operator, and no mechanism to opt out of routing through address space with the characteristics documented in Sections 4.1–4.2. Section 5.3 also reports a finding independent of that stewardship-gap thesis — evidence that this kind of exposure isn't limited to dormant or unstewarded ASNs.

### 5.1 Inherited Reputation

Address space does not arrive clean. AS11427's prefix composition includes AFRINIC ERX blocks and Cloud Innovation Ltd secondary-market space with routing and reputation histories entirely disconnected from the Charter subscribers whose traffic may traverse it. A subscriber has no way to know that the IP address assigned to them carries a blocklist history, spam reputation, or prior abuse association accumulated by a completely different, unrelated party before the space was folded into a zombie-routed block. This creates the potential for direct, individual harm: legitimate traffic — email, VPN connections, authenticated sessions — could be blocked, flagged, or rate-limited by downstream services relying on IP reputation, for reasons the subscriber would have no way to diagnose and no relationship with the responsible party to resolve. This paper documents the condition that creates this exposure, not an observed instance of it.

### 5.2 Anomalous Routing Exposure

At the 2026-05-05 baseline, confirmed zombie ASNs in this investigation's evidence base showed upstream transit relationships inconsistent with their documented domestic customer base (whether the control ASNs show the same relationships has not yet been checked; Section 4.2) — international Tier 1 peers (Telstra, PCCW, SingTel, Arelion) appearing on ASNs that, per their registration history, should carry only regional US traffic. A subscriber whose traffic is routed through such a path experiences this invisibly: added latency, additional international hops, and — more significantly — traffic traversing networks and jurisdictions the subscriber never agreed to and has no reason to expect. This is not a claim that any specific subscriber's traffic has been intercepted; it is a claim that the routing path itself is inconsistent with what a domestic residential or business subscriber should reasonably expect, and that inconsistency is invisible to the person experiencing it.

### 5.3 Malicious Infrastructure in Actively-Operated Carrier Space

Section 4.3 documents that AS7046 is a normally, continuously operated Verizon customer-aggregation ASN, not dormant or unstewarded. That correction does not remove the underlying observation: a domain was discovered through this investigation's own AS7046 validation testing (Level 3 passive DNS hunting), with no reliance on any prior external report, associated by passive DNS (Robtex reverse lookup; first record last seen 2026-06-16T20:08:25Z) with addresses in two of AS7046's announced address blocks, on two separate occasions two months apart, both blocks independently confirmed as announced by AS7046 via direct RIPEstat prefix-list query (Section 8.1b). This establishes that, as of the recorded last-seen times, hostnames under the domain were associated with addresses inside prefixes AS7046 was announcing. It does not establish what traffic, if any, those addresses carried. The domain is characterized as malicious on the basis of its infrastructure behavior: rotation across subdomains and separate address blocks (two different subdomains in two different AS7046 /24s, two months apart; Section 8.1b), and movement across networks. Sandbox resolution data, used here as validation only (Section 3.7), show the domain resolving across runs to addresses in networks unrelated to AS7046, with a 5-second TTL in the earliest report. Registry and routing records for each address on its observation date (2026-10-20 acquisition, Section 8.1b) place them as follows: `123.150.3.39` was originated by AS17638 (China Telecom, Tianjin); `145.74.110.172` was originated by AS1103 (SURF, the Dutch research network, in a university's registered block); and `148.17.131.206`, in the earliest report, sits in DoD-registered space that no network announced at the time — a resolution to an unreachable address. A third party's sandbox submission four months before this investigation's discovery is consistent with this, but the discovery did not rely on it. This is arguably a more concerning finding than the paper's original framing, not a weaker one — it means this kind of exposure is not confined to space nobody is watching. Space that a legitimate business customer's infrastructure planning would reasonably assume is properly assigned and monitored can still surface unrelated malicious activity, with no connection to the ASN's actual operator. Any monitoring, security tooling, or threat-intelligence system that associates network behavior with the announcing ASN or its registered organization risks misattributing this activity to Verizon Business/UUNET, an organization with no established operational connection to it.

### 5.4 Loss of Accountability

Across every confirmed finding in Section 4, the common thread is not malicious intent on the part of the original carrier — it is the absence of anyone accountable for the space at all. A subscriber experiencing a routing or security problem traceable to zombie-routed address space has no clear party to contact: not the original carrier (which no longer operates the space and, in several cases documented in Section 8, may not know it is still routing), not the acquiring carrier (which has no visibility into space it never took over), and not ARIN (which maintains the registration record but has no operational role in troubleshooting). This is the structural harm underlying every specific example above: address space with no accountable operator produces no clear remediation path when something goes wrong, regardless of whether "something going wrong" is a reputation problem, a routing anomaly, or hosted malicious infrastructure.

---

## 6. Conclusion

### 6.1 What This Paper Established

The thesis stated in Section 2.2 — that dormant and unassigned Autonomous System space constitutes a persistent, exploitable attack vector separate from ordinary administrative lag — is supported by the evidence in Section 4, with the specific evidentiary bar set in Section 2.4 (the administrative-lag null hypothesis) applied consistently rather than assumed away. The cross-ASN signature predicted in Section 2.2 — the same non-carrier secondary-market sub-allocator appearing across multiple, otherwise-unrelated dormant carrier ASNs — is confirmed in one instance (AS11427) and supported by one pending lead (AS7029) (Section 4.1). The null hypothesis did real analytical work rather than functioning as a formality: eight candidate ASNs were cleared against it for the two that rejected it (Section 4.2, Table 4.1), and three of those clearances — AS10913, AS6181, and AS7046 — demonstrate the methodology catching its own errors at different points in the process: two before and after external filing (Section 4.2), and one during peer review, after this paper was already posted publicly (Section 4.3). AS7046's retraction is, if anything, the sharper demonstration of the discipline this paper argues for: a candidate finding investigated, checked against fresh primary evidence, and corrected in public rather than left standing.

### 6.2 Limitations

This paper's evidence base is drawn from a single investigation's sampling frame (Section 3.5), seeded from specific geographic nodes and subsequently expanded, not from a systematic census of all ARIN-region ASNs. The confirmed findings should be read as case-study depth on a real, bounded set of carrier ASNs, not as a population-level estimate of how common this pattern is across the internet's full address space. The methodology itself has a documented limitation (Section 3.8): BGP activity and RDAP authorization gaps alone cannot always distinguish malicious squatting from other administrative causes without the kind of cross-referencing this investigation performed — a limitation independently corroborated by academic literature located after this investigation's methodology was already in place (Nemmi et al., 2021; see the chronology note in Section 2.2). Finally, as demonstrated directly by Section 4.4's retraction, a routing anomaly observed through remote digital methods alone can be a genuine network event or a monitoring-instrument artifact, and distinguishing the two requires checking the instrument's own contemporaneous behavior — including on unrelated control ASNs — not just the anomalous ASN in isolation. This paper is explicit that it did not do so on the first pass, and that the correction only happened because the original working notes were preserved and re-checked.

### 6.3 A Further Question This Paper Raises But Does Not Answer

An earlier draft of this section asked whether disclosure of a vulnerable ASN produces durable remediation or only a temporary lull before reoccupation, built on AS7046 having gone dark and then been reoccupied. Section 4.4 removes the premise this question depended on — AS7046 was never confirmed dark, so there is no gap to have been "reoccupied." That specific framing does not survive this revision.

A narrower, still-open question survives it: `bybanking.com` was found resolving into two different AS7046-announced blocks, two months apart, within an ASN that was continuously and normally operated throughout. Why a malicious domain would resurface twice in the same carrier's customer-aggregation space — a compromised or complicit customer, unauthorized subletting of an assigned block, or something else — is not established by the evidence in hand, and this paper does not speculate further than that. A separate limitation compounds the uncertainty: the passive-DNS tool used returned only a last-seen timestamp for both records, with no first-seen date captured (Section 8.1b) — meaning even the two-months-apart framing describes when the records were *queried*, not necessarily how long each resolution had actually been live. This paper flags both the narrower question and this evidentiary limitation; it does not have the data to resolve either. Appendix A documents the hunt that produced the finding and the longitudinal design through which this question is now being pursued (A.7): occupancy and stewardship measured separately, cause-agnostic, with the full evidence base observed as controls in every window.

### 6.4 Closing

Unassigned and dormant Autonomous System space is not a bookkeeping curiosity left over from decades of carrier consolidation. It is address space with no accountable current operator, and the evidence in this paper shows that gap being used: secondary-market address space with no acquisition-history explanation, routed through a dormant carrier ASN (Section 4.1). Separately, the evidence shows malicious infrastructure surfacing even in carrier space that is actively operated (Section 5.3), so exposure of this kind is not confined to dormant ASNs. The internet's routing system has no built-in mechanism that requires an ASN to prove it is still accountable to anyone. Until it does, this attack surface will keep being available to whoever finds it next.

---

## 7. Bibliography

Guilmette, R. F. (2018, June 26). *AS3266: BitCanal hijack factory, courtesy of Cogent, GTT, and Level3* [Mailing list message]. NANOG. https://mailman.nanog.org/pipermail/nanog/2018-June/096034.html

Kumari, W., Bush, R., Schiller, H., & Patel, K. (2015). *Codification of AS 0 processing* (RFC 7607). Internet Engineering Task Force. https://doi.org/10.17487/RFC7607

Madory, D. (2018, July 12). *Shutting down the BGP hijack factory*. APNIC Blog. https://blog.apnic.net/2018/07/12/shutting-down-the-bgp-hijack-factory/ (Adapted from the original Dyn Blog post, https://dyn.com/blog/shutting-down-the-bgp-hijack-factory/, whose parent domain has a documented history of link rot following Oracle's acquisition of Dyn; the APNIC mirror was verified live 2026-08-25 and is cited here as the more durable source.)

National Institute of Standards and Technology. (2019, December). *Resilient interdomain traffic exchange: BGP security and DDoS mitigation* (NIST Special Publication 800-189; K. Sriram & D. Montgomery). U.S. Department of Commerce. https://doi.org/10.6028/NIST.SP.800-189

Testart, C., Richter, P., King, A., Dainotti, A., & Clark, D. (2019). Profiling BGP serial hijackers: Capturing persistent misbehavior in the global routing table. In *Proceedings of the Internet Measurement Conference (IMC '19)* (pp. 420–434). Association for Computing Machinery. https://doi.org/10.1145/3355369.3355581

Nemmi, E. N., Sassi, F., La Morgia, M., Testart, C., Mei, A., & Dainotti, A. (2021). The parallel lives of Autonomous Systems: ASN allocations vs. BGP. In *Proceedings of the ACM Internet Measurement Conference (IMC '21)*, 19 pages. Association for Computing Machinery. https://doi.org/10.1145/3487552.3487838

*Note: verified 2026-07-30 against the original ACM PDF (analyst-provided). Two corrections applied: (1) the author list was previously copied from the 2019 Testart et al. entry — actual 2021 authors are Nemmi, Sassi, La Morgia, Testart, Mei, and Dainotti (Testart is 4th author, not 1st). Per analyst direction (2026-07-30), all six in-text citations of this source (Sections 2.1, 2.2, 2.3, 3.8, 4.1, 6.3) have been updated from "Testart et al. (2021)" to "Nemmi et al. (2021)" to match; the 2019 paper (genuinely first-authored by Testart) is unaffected and still cited as "Testart et al. (2019)" throughout. (2) DOI confirmed correct (10.1145/3487552.3487838); ACM lists this as a 19-page article, not a continuous page range — "page range" as originally requested does not apply to this citation format. NIST SP 800-189 verified 2026-10-20 against the NIST CSRC record (final, 2019-12-17; authors Sriram and Montgomery; DOI as listed); Section 2.1, "Prefix Hijacking and Announcement of Unallocated Address Space," names both announcement of unallocated address space and prefix squatting.*

---

## 8. Evidence Log
*Backwater Forensics | VRF#26-04-TPWXX | Culled for peer review 2026-07-29, updated 2026-10-20: full per-file evidence tables retained only for the six ASNs that move or control the paper's arguments (Sections 4.1–4.2); all other ASNs summarized to one row each. **215 evidence-file references** are represented in aggregate across this log (per-ASN sections plus the batch/multi-ASN summary in 8.2) — a straight sum, recomputed 2026-10-20 (60 in 8.1b + 64 in 8.1c + 91 in 8.2 = 215; 8.1b rose from 58 with the two 2026-10-20 origin-check runs). A file cited under more than one ASN (e.g., the BLOCK 3-4 synthesis) is counted once per citation, and several pDNS re-runs are byte-identical by hash, so the count of distinct files is lower (`SHADOW_MARKET_FILE_HASHES.txt`). 8.1c's count moved from 63 to 64 with the addition of `ASN8069-MSN-output.txt`, the AS8069 resolution evidence. Full per-file hashes for every file — summarized or not — remain in `SHADOW_MARKET_FILE_HASHES.txt`, which is unaffected by this cull. 6 files excluded as out-of-scope (analyst-scoped, dated 2026-07-11) and 4 files (AS702/AS2686/AS5650/AS14905 pDNS run) confirmed in-scope as comparison/control evidence.*
### 8.1 Corrections on File
| ASN | Correction | Filed as | Status |
|---|---|---|---|
| AS10913 | TRUE ZOMBIE (filed 2026-05-02) -> LEGITIMATE_SUCCESSOR | CISA CORRECTION-002 | Retracted post-disclosure |
| AS11427 | CLEAN (Phase A) -> THIRD_PARTY_CONTROL / ZOMBIE | CISA CORRECTION-001 | Corrected post-disclosure |
| AS6181 | TRUE ZOMBIE (Insight) -> FALSE_POSITIVE (Cincinnati Bell/FUSE-NET) | Not filed — caught pre-disclosure | Corrected in baseline register 2026-05-05, before any CISA/FBI transmission. Internal record `FALSE-POSITIVE-ALERT-AS6181-CISA-SUPPLEMENT-VRF26-04-TPWXX.txt` documents the correction on Backwater Forensics' own side; its CISA-styled filename reflects the intended-format convention, not an actual transmission. No retraction required. |

### 8.1b Full Evidence — Load-Bearing ASNs

The six ASNs below carry direct citations in Sections 4.1–4.4 and retain full per-file evidence tables.

### AS6181 — FUSE-NET — Cincinnati Bell Telephone Company LLC
**Status:** FALSE_POSITIVE | **Case ref:** CASE-008 | **Confidence tier:** R | **Evidence files:** 3

> CORRECTED PRE-DISCLOSURE. RDAP (AS6181-DEETS.txt, 2026-07) confirms registrant is Cincinnati Bell (FUSE-NET), not Insight. Attribution error caught and corrected in baseline register by 2026-05-05, before any CISA/FBI transmission. Note on provenance: the ZOMBIE-ASN-REGISTRY.db `source_ref` for this entry (`FALSE-POSITIVE-ALERT-AS6181-CISA-SUPPLEMENT-VRF26-04-TPWXX.txt`) is an internal Backwater Forensics record documenting the correction — despite the filename, it was never transmitted to CISA. Timing meant AS6181 was already resolved before any CISA filing cycle that would have included it; neither the original zombie characterization nor the correction record ever left this investigation. See correction note below.

| Date | File | Type |
|---|---|---|
| 2026-05-03 | `prefixes_AS6181_20260503_170109.json` | Level 5 — BGP/Prefix |
| 2026-05-03 | `sample_ips_AS6181_20260503_170109.txt` | Level 5 — BGP/Prefix |
| 2026-05-08 | `pdns_AS6181_20260508_193449.json` | Level 3 — Passive DNS |
| 2026-06-18 | `rdap-batch-20260618_024735.txt` [shared: multi-ASN] | Level 5 — BGP/Prefix (RIPEstat routing-status; confirms AS6181 live/active, 116 prefixes) |
| 2026-07-12 | `AS6181-DEETS.txt` | **Level 4 — RDAP/WHOIS (registrant confirmation).** Direct `rdap.arin.net/registry/autnum/6181` pull. Registrant: Cincinnati Bell Telephone Company LLC (CBTL-6). Resolves the AS6181 attribution conflict definitively. |

### AS7015 — COMCAST-7015 — Comcast-operated TCI legacy, 159 downstream customers
**Status:** ZOMBIE_TRANSIT (Tier R, 2026-05-05) — **restored; dark-window reclassification retracted 2026-08-25** | **Case ref:** CASE-002/003 | **Confidence tier:** R | **Evidence files:** 13

> Corrected twice now. Previously written at Tier A — overstated, corrected to Tier R (Section 3.2/3.4). Then, on 2026-08-25 peer review, a subsequent dark-window reclassification was itself retracted: the analyst's own 2026-05-22 contemporaneous note states "NOT going dark; status: ZOMBIE_TRANSIT restored," identifying the underlying cause as RIPEstat query timeouts and a documented automated-monitoring failure (`MONITOR FAILURE — sandbox 403`) that also affected CLEAN control ASN AS7922 on the same dates — not a real routing withdrawal. AS7015's status reverts to its 2026-05-05 baseline: ZOMBIE_TRANSIT at Tier R (routing/upstream inconsistency and international registry records — `bgp_neighbors_*`, `bgp_path_AS7015_intl_batch.txt`, `whois_apnic_AS7015_20260505.txt`, `whois_AS7015_intl_20260505.txt`), unaffected by this correction. `originas` gaps are no longer counted toward it (Section 3.4); the control comparison for its international upstreams is queued. See Section 4.4 for the full retraction record.

| Date | File | Type |
|---|---|---|
| 2026-05-05 | `bgp_announced_AS7015_20260505_034213.txt` | Level 5 — BGP/Prefix |
| 2026-05-05 | `bgp_neighbors_AS7015_20260505_034115.txt` | Level 5 — BGP/Prefix |
| 2026-05-05 | `bgp_neighbors_AS7015_20260505_034128.txt` | Level 5 — BGP/Prefix |
| 2026-05-05 | `bgp_routing_history_AS7015_20260505_034008.txt` | Level 5 — BGP/Prefix |
| 2026-05-05 | `dns_AS7015_intl_20260505_020656.txt` | Level 3 — DNS/PTR check |
| 2026-05-05 | `prefixes_AS7015_20260505_010528.json` | Level 5 — BGP/Prefix |
| 2026-05-05 | `sample_ips_AS7015_20260505_010528.txt` | Level 5 — BGP/Prefix |
| 2026-05-05 | `whois_AS7015_intl_20260505.txt` | Level 4 — RDAP/WHOIS |
| 2026-05-05 | `whois_apnic_AS7015_20260505.txt` | Level 4 — RDAP/WHOIS |
| 2026-05-05 | `whois_arin_AS7015_20260505.txt` | Level 4 — RDAP/WHOIS |
| 2026-05-08 | `pdns_AS7015_20260508_174745.json` | Level 3 — Passive DNS |
| 2026-05-05 | `BLOCK 3-4 — BONUS- AS7015-8069.txt [shared: AS8069]` | Analyst synthesis |
| 2026-05-05 | `bgp_path_AS7015_intl_batch.txt` | Level 5 — BGP/Prefix |

### AS7029 — Windstream Communications LLC
**Status:** WINDSTREAM_RECLAIM | **Case ref:** CASE-010 | **Confidence tier:** R | **Evidence files:** 7

> Prior CONTROL_LOST characterization retracted (CISA CORRECTION log UPDATE-002).
>
> **Not yet verified — correction to a prior draft (2026-08-18):** an earlier version of this note claimed this association was "confirmed via live RDAP check, 2026-07-15." That claim was made without a saved artifact to support it and has been retracted. The full `rdap-batch-20260506_022253.txt` batch (8 blocks: AS6478, AS7922, AS8069, AS7132, AS20115, AS5650, AS10913, AS7029) was checked directly and confirmed to contain only ASN-level registrant lookups — no query on `154.194.16.0/21` or any block-level record appears anywhere in it. The LARUS-SERVICE-MNT/Cloud Innovation Ltd association on `154.194.16.0/21` — the second half of Section 4.1's cross-ASN signature — remains documented only in `CISA-CORRECTION-AGGREGATE-VRF26-04-TPWXX.md` [NEW-001], with no independent block-level RDAP confirmation on file. `asn_source.json`'s silence on this block is a thin watchlist config, not a full analytic record, so it isn't treated as a contradiction — but this needs a direct RDAP query on `154.194.16.0/21`, likely via AFRINIC (Cloud Innovation Ltd is a Seychelles/AFRINIC secondary-market registrant, outside ARIN's authoritative region), before Section 4.1 can rely on it as a second confirmed instance. Not yet resolved either direction.
>
> **Routing check (research log I-071/I-072).** RIPEstat shows `154.194.16.0/21` absent from AS7029's announced IPv4 prefixes (first pass undated; dated rerun 2026-08-17, identical result). Five 154.x.x.x /24s are announced (`154.6.228.0/24`, `154.6.229.0/24`, `154.6.230.0/24`, `154.16.13.0/24`, `154.30.152.0/24`); their registrants are the next check. The original archival batch (`rdap-batch-20260506_022253-7029.txt`) holds ASN-level data only (Windstream Communications LLC, WINDS-6; 2,674 IPv4 prefixes) and cannot place the /21 in time.

| Date | File | Type |
|---|---|---|
| 2026-05-05 | `dns_AS7029_state_change_20260505_020107.txt` | Level 3 — DNS/PTR check |
| 2026-05-05 | `prefixes_AS7029_20260505_012337.json` | Level 5 — BGP/Prefix |
| 2026-05-05 | `prefixes_AS7029_20260505_015744.json` | Level 5 — BGP/Prefix |
| 2026-05-05 | `sample_ips_AS7029_20260505_012337.txt` | Level 5 — BGP/Prefix |
| 2026-05-05 | `sample_ips_AS7029_20260505_015744.txt` | Level 5 — BGP/Prefix |
| 2026-05-08 | `pdns_AS7029_20260508_192335.json` | Level 3 — Passive DNS |
| 2026-05-08 | `pdns_AS7029_20260508_193215.json` | Level 3 — Passive DNS |

### AS10913 — INTERNAP-BLK / Unitas Global (EarthLink successor)
**Status:** LEGITIMATE_SUCCESSOR | **Case ref:** CASE-010 | **Confidence tier:** R | **Evidence files:** 10

> Formal retraction on file: CISA CORRECTION-002. Originally filed TRUE ZOMBIE (2026-05-02 supplemental); revised and retracted 2026-05-05 after Phase C confirmed Unitas Global as legitimate successor.

| Date | File | Type |
|---|---|---|
| 2026-05-03 | `prefixes_AS10913_20260503_170109.json` | Level 5 — BGP/Prefix |
| 2026-05-03 | `sample_ips_AS10913_20260503_170109.txt` | Level 5 — BGP/Prefix |
| 2026-05-05 | `prefixes_AS10913_20260505_012337.json` | Level 5 — BGP/Prefix |
| 2026-05-05 | `prefixes_AS10913_20260505_015744.json` | Level 5 — BGP/Prefix |
| 2026-05-05 | `sample_ips_AS10913_20260505_012337.txt` | Level 5 — BGP/Prefix |
| 2026-05-05 | `sample_ips_AS10913_20260505_015744.txt` | Level 5 — BGP/Prefix |
| 2026-05-05 | `whois_arin_AS10913_20260505.txt` | Level 4 — RDAP/WHOIS |
| 2026-05-08 | `pdns_AS10913_20260508_192335.json` | Level 3 — Passive DNS |
| 2026-05-08 | `pdns_AS10913_20260508_193215.json` | Level 3 — Passive DNS |
| 2026-05-05 | `prefixes_AS10913_survived.txt` | Level 5 — BGP/Prefix |

### AS11427 — TWC-11427-TEXAS — Charter ARIN, BGP operator unknown
**Status:** THIRD_PARTY_CONTROL | **Case ref:** CASE-001 | **Confidence tier:** R | **Evidence files:** 8

> Formal correction on file: CISA CORRECTION-001. Zone anchor status; Cloud Innovation Ltd / LARUS-SERVICE-MNT secondary-market pattern (see NEW-001, cross-referenced with AS7029).
>
> **Level 4 basis:** registrant prong (Section 3.4), not `originas`. **Open:** AFRINIC's own record for the 156.x ERX range, and an IRR/RPKI check on the Cloud Innovation blocks, the claim actually in dispute (log supplement, P2-5).

| Date | File | Type |
|---|---|---|
| 2026-05-05 | `dns_AS11427_state_change_20260505_020451.txt` | Level 3 — DNS/PTR check |
| 2026-05-05 | `prefixes_AS11427_20260505_012337.json` | Level 5 — BGP/Prefix |
| 2026-05-05 | `prefixes_AS11427_20260505_015744.json` | Level 5 — BGP/Prefix |
| 2026-05-05 | `sample_ips_AS11427_20260505_012337.txt` | Level 5 — BGP/Prefix |
| 2026-05-05 | `sample_ips_AS11427_20260505_015744.txt` | Level 5 — BGP/Prefix |
| 2026-05-05 | `whois_arin_156x_AS11427_20260505.txt` | Level 4 — RDAP/WHOIS |
| 2026-05-05 | `whois_arin_AS11427_20260505.txt` | Level 4 — RDAP/WHOIS |
| 2026-05-08 | `pdns_AS11427_20260508_174745.json` | Level 3 — Passive DNS |

### AS7046 — RFC2270-UUNET-CUSTOMER (Verizon Business / MCICS)
**Status:** **NORMALLY OPERATED — reclassified 2026-08-25 (two earlier labels retracted; see note); malicious domain found via this investigation's own AS7046 validation testing (see 5.3)** | **Case ref:** CASE-005 (WorldCom/MCI/UUNET lineage) | **Confidence tier:** R (bybanking.com finding only — see note) | **Evidence files:** 19

> **Reclassified 2026-08-25, on round-1 peer review + direct evidence recheck.** Two prior labels both assumed AS7046 was dormant or unstewarded federal space. Two pieces of evidence checked this pass do not support that: (1) AS7046's registration, `RFC2270-UUNET-CUSTOMER`, describes an ordinary shared-ASN function for a provider's single-homed customers — continuous full visibility is the expected state for this ASN type, not an anomaly. (2) A fresh RIPEstat upstream-neighbor query (2026-08-25, window matched to the existing AS7015 reference pull) found three of AS7046's five upstream peers are themselves Verizon Business/MCICS-registered sibling ASNs, with AS701 — Verizon's own UUNET backbone — as the dominant relationship by a wide margin (connectivity power 6752 against a next-highest of 278). This is what a normally operated carrier customer-aggregation ASN's upstream table looks like, not what a third-party-controlled one looks like. The "reoccupied twice" narrative built on a "disruption" that Section 4.4 separately retracted — no dark window was ever confirmed for this ASN, so there is no gap for the space to have been "reoccupied" from. What is retained, because it does not depend on any of the retracted framing: `bybanking.com`, a domain this investigation discovered on its own through Level 3 passive DNS hunting against AS7046 — not via any prior external report — was found resolving into two of AS7046's announced blocks, two months apart, both independently confirmed as genuinely announced by this ASN. That finding is reported in full below and in Section 5.3.
>
> **RDAP originas data (reframed, per peer review P1-3).** Five IPv6 blocks — `WIRE-V6`, `TERRENAP-V6`, `CFTC-NETWORK`, `DOLNET`, and `CMMS-IPV6` (identified in a later re-check, 2026-07-15; its registrant name is consistent with, but not independently confirmed as, the Centers for Medicare & Medicaid Services) — all return `originas: []` on RDAP, re-confirmed 2026-07-15. On round-1 peer review, this field was treated too strongly in the prior draft: an empty `originas` is RDAP's optional/default state, not a routing-authorization mechanism — RPKI ROAs and IRR objects are the actual authoritative record. RPKI validation checked directly against three of the five blocks (2026-08-25) returned `status: unknown` (no covering ROA published) for all three — indeterminate, not `invalid` (which would support the original claim) and not `valid` (which would refute it). TERRENAP-V6's actual announced prefix was identified (`2001:4868:207::/48`, one of six /48s AS7046 announces under its parent /32 — itself a pattern consistent with normal customer-block allocation) but its RPKI check has not yet completed; CMMS-IPV6 has not yet been checked. This is logged as in-progress, not resolved either direction.
>
> Corroborated by the technical POC (OA12-ARIN) remaining unvalidated by ARIN since 2022-11-02, confirmed unchanged as of 2026-07-15 — an administrative gap consistent with the RFC 2270 customer-aggregation reading (Section 4.3) and not, on its own, evidence of unauthorized control.
>
> **Cross-ASN claim ruled out.** A prior registry note suggested the CFTC-NETWORK block (`2620:0:250::/48`) also appeared in AS11427. Direct RIPEstat check of AS11427's full IPv6 prefix list (2026-07-14) shows this is **not the case** — the two ASNs' IPv6 space is entirely disjoint. This does not go into Section 4.1's cross-ASN pattern discussion; it was checked and did not hold up.
>
> **External corroboration of carrier identity (added 2026-07-30).** Nemmi et al. (2021), independent of this investigation, document AS7046 in an unrelated case study (Section 6.4, "Unallocated ASNs used internally leak to the global Internet"): an unallocated ASN (AS290012147) announced a covered /24 for over two years (2015–2017), with the observed AS path forming the triplet `{AS290012147, AS7046, AS701}`. The authors state both AS701 and AS7046 were held by Verizon at the time, and attribute the leak to an internal Verizon misconfiguration — not third-party occupation. This predates this investigation's evidence by roughly a decade and is now read differently than in the prior draft: it is early, independent, external confirmation of exactly what the 2026-08-25 upstream-neighbor check also found — **Verizon has operated AS7046 continuously, including at least a decade before this investigation began.** It supports Section 4.3's reclassification, not the paper's original stewardship-gap framing.
>
> **Discovery, stated precisely.** A domain was discovered independently — through this investigation's own AS7046 validation testing (Level 3 passive DNS hunting), with no reliance on any prior external report — associated by passive DNS (Robtex reverse lookup) with addresses inside AS7046's actively-announced address space. This establishes an association between the domain's hostnames and those addresses as of the recorded last-seen times; it does not establish what traffic, if any, those addresses carried. A separate party had previously submitted the same domain to Hybrid Analysis approximately four months earlier — a report this investigation did not rely on to make its own discovery. The domain's malicious characterization rests on its rotation across subdomains, address blocks and networks (below), with sandbox resolution data used as validation only (Section 3.7).
>
> **bybanking.com — two independent blocks, two months apart.** Level 3 pDNS (2026-06-16; first pDNS run on AS7046, 20 of 219 prefixes and 100 IPs sampled, one record returned — research log I-047): subdomain `9ve2e267.bybanking.com` associated with `161.162.17.104` in `161.162.17.0/24`, last seen 2026-06-16T20:08:25Z. A second pDNS run (2026-07-15): `ns-5whj.bybanking.com` associated with `198.57.13.170` in `198.57.13.0/24` — a different subdomain, IP, and /24 entirely. Both blocks independently confirmed as genuinely announced by AS7046 via direct RIPEstat prefix-list query, not inferred from the pDNS tool's internal sampling. Two separate blocks two months apart is a recurrence, not a single stale record — subject to the last-seen-only limitation in Section 6.3.
>
> **Sandbox data — validation only (Section 3.7).** Six Falcon Sandbox reports are on file: one third-party (Feb 9, 2026, analysis `6989f42c...`, found via search, predating this investigation's involvement) and five submitted by this investigation (2026-06-16 to 2026-07-25). Only their DNS resolution observations are used, and only to validate the rotation pattern established by Level 3 pDNS above. Resolutions recorded: `148.17.131.206` (US, Feb, TTL 5 seconds — anomalously low relative to the 300–3600 second range typical of legitimate infrastructure); the Netherlands (Jul 25, W10 run); and `123.150.3.39` (China, Jul 25, W11 run). Across runs the domain resolved to addresses in three countries, consistent with the rotation seen in pDNS.
>
> **Origin of each sandbox-observed address on its observation date (acquired 2026-10-20; RIR RDAP, Src-R; RIPEstat routing-history ±3 days, Src-S; only prefixes covering the address counted).** `123.150.3.39` (2026-07-25): APNIC record CHINANET-TJ; covered by `123.150.0.0/15` and `123.150.0.0/16`, both originated by AS17638 (China Telecom, Tianjin), visible to 325–330 RIS peers. `145.74.110.172` (2026-07-25): RIPE record HAN-NET (Hogeschool van Arnhem en Nijmegen), covered by `145.74.0.0/15`, originated by AS1103 (SURF B.V.), visible to 327–331 peers; a university network address is consistent with a compromised or misused host but does not establish one. `148.17.131.206` (2026-02-09): ARIN record DNIC-SNET-148-010 (DoD Network Information Center; `148.10.0.0`–`148.50.255.255`, registered 2025-08-26); no announcement of the registered `148.16.0.0/12` or any more-specific prefix covering the address appears in RIS routing history for 2026-02-06 to 2026-02-12, and none today. On that date the domain resolved to an address no network routed. The plain reading is a DNS record pointing to an unreachable address, a common state for an idle or decoy malicious domain; it implies nothing about the address holder. RIS is a broad sample of the global table, not all of it, so a narrowly scoped announcement outside RIS's view is not excluded. AS7046 originated none of the three.
>
> **Demotion, decided 2026-08-25.** The five investigation-submitted analyses were deliberate exceptions to the standing sandbox-resubmission protocol. On review, sandbox output does not belong in the paper's primary evidentiary base: a sandbox measures how a domain responds to *being sandboxed* — a different signal from its routing, DNS, or authorization history, and one this investigation's own repeated submissions could influence. The escalating-verdict narrative these runs previously supported is withdrawn, and no verdict or threat score is cited for any claim. Their DNS resolution observations are cited as validation only, as above. The files and their hashes are retained in full for chain-of-custody completeness (Section 8, `SHADOW_MARKET_FILE_HASHES.txt`).
>
> **The China-resolving block was directly checked against AS7046 and is not part of it.** Live RIPEstat query (2026-07-26) against AS7046's full IPv4 prefix list confirms `123.150.3.39` does not fall within any AS7046-announced block. This is the first confirmed instance of `bybanking.com` resolving entirely outside AS7046's address space, and confirms the *domain* has moved off this ASN's space. It has no bearing on Section 4.3's reclassification of the ASN itself — that assessment rests on the upstream-neighbor and RFC 2270 evidence, not on the domain's current resolution pattern. The address came from a sandbox resolution (validation only); the finding that it lies outside AS7046 rests on the direct RIPEstat routing query, confirmed by the 2026-10-20 origin check above (AS17638).
>
> **Current routing state (re-confirmed 2026-07-14/15):** 220 IPv4 prefixes, 24 IPv6 prefixes, 100% RIS visibility (326/326 IPv4 peers, 321/321 IPv6 peers), last seen 2026-07-14T16:00:00. Not dark, not dormant — fully visible in global BGP routing as of this writing.
>
> **What this does not establish** (per the source finding's own limits, carried forward under the actor-agnostic framing in Section 2.3): why `bybanking.com` specifically surfaced in this ASN's customer space; who operates the domain; what traffic, if any, the associated addresses carried; or why the domain resolved, in February, to unannounced DoD-registered space. Framing in the original draft that assumed a stewardship gap has been retracted (Section 4.3) and is not asserted in this revision.
>
> **Reporting status — corrected.** The original source finding claimed AS7046 was "reported to CISA + FBI 2026-05-02." Direct text search of the actual filed 2026-05-02 CISA supplemental and both versions of the correction aggregate log confirms **zero mentions of AS7046 in any of them** — and the claim is chronologically impossible regardless, since AS7046 wasn't a named candidate in this investigation's own batch planning until after that date, and its Tier R confirmation didn't occur until 2026-05-27. The finding was actually transmitted via IC3 on **2026-07-16**.
>
> **Reporting delay — flagged as a process concern, not minimized.** The bybanking.com finding was discovered 2026-06-16 and not actually reported until 2026-07-16 — **exactly 30 days.** The proximate cause is on record: the 2026-06-16 finding document's own "Report Status" section stated AS7046 had already been reported on 2026-05-02 and that "no additional disclosure action is required." That belief was false, but nothing tested it until this paper's drafting process independently swept the actual CISA filings weeks later and found no record of it. For a malicious domain, a documentation error that goes unchecked for 30 days is not a minor bookkeeping issue — it is 30 days the domain continued operating unflagged to any external party who could act on it. This is logged here as a concrete illustration of the broader methodological point already made elsewhere in this paper (Section 2.5's "cleared findings are retained" principle, and the AS10913/AS6181 cases): an unverified claim about disclosure status is itself a finding that needs the same evidentiary discipline as any other, and this is the one case in this investigation where that discipline was applied too late to prevent real-world consequence.

| Date | File | Type |
|---|---|---|
| 2026-02-09 | Falcon Sandbox report, `bybanking-february-2026.pdf` (analysis `6989f42c...`) | Third-party sandbox report — pre-existing, found via search; validation only (DNS resolution) |
| 2026-05-23 | RDAP originas batch — `7046--confirmed--FF.txt` (raw RDAP queries, primary source; `FF 2.txt` and `FF 3.txt` are byte-identical copies of the same 04:18 check, one observation; Tier R confirmation recorded 2026-05-27) | Level 4 — RDAP/WHOIS (supporting only; Section 3.4) |
| 2026-06-16 | `BIV-ANO-2026-06-16_AS7046-PDNS-BYBANKING.md` | Level 3 — Passive DNS + analyst synthesis |
| 2026-06-16 | Falcon Sandbox report, `bybanking-june-2026.pdf` (analysis `6a31af53...`) | **Investigation-submitted** — reactivation check; validation only |
| 2026-06-16 | `BIV-PND-2026-06-16_SESSION-PAUSE-STATE.md` | Session state / procedural record |
| 2026-07-15 | Second pDNS finding — `198.57.13.0/24`, `ns-5whj.bybanking.com` | Level 3 — Passive DNS |
| 2026-07-14/15 | Live re-confirmation — RDAP (5 blocks), RIPEstat routing-status, ASN-level RDAP, AS11427 cross-check | Level 4/5 — RDAP + BGP, current as of filing |
| 2026-07-15 | Falcon Sandbox report, `bybanking-july-2026-win11.pdf` (analysis `6a56f6183bcc...`, 02:53 UTC) | **Investigation-submitted** — reactivation check; validation only |
| 2026-07-15 | Falcon Sandbox report, `bybanking-july-2026-win10.pdf` (analysis `6a56fdb39723...`, 03:25 UTC) | **Investigation-submitted** — reactivation check; validation only |
| 2026-07-15 | `CISA-FBI-INITIAL-AS7046-BYBANKING-2026-07-15.txt` | Drafted disclosure filing, superseded the earlier `CISA-SUPPLEMENTAL-...` draft. |
| 2026-07-16 | IC3 filing confirmation, Submission ID `1ac64da023d24387bc4e6dd811b8c456` | **Transmitted.** 30 days after the underlying finding (2026-06-16). See reporting-delay note above. |
| 2026-07-25 | Falcon Sandbox report, `HA-072726-bybanking-dot-com-W11.pdf` (analysis `6a640572395a8786460e0c4c`, 00:38:11 UTC) | **Investigation-submitted** — validation only; resolution: China (`123.150.3.39`); verdict not relied on |
| 2026-07-25 | Falcon Sandbox report, `HA-072726-bybanking-dot-com-W10.pdf` (analysis `6a64054fcf58877fc3076b10`, 00:37:36 UTC) | **Investigation-submitted** — validation only; resolution: Netherlands; verdict not relied on |
| 2026-07-26 | Live RIPEstat check — `123.150.3.39` confirmed **not** in AS7046's announced IPv4 space | Level 5 — BGP/Prefix, current as of filing |
| 2026-10-20 | Origin check, run `IPORIGIN-20261020-050622Z` — `123.150.3.39`, `145.74.110.172`: RIR RDAP + RIPEstat routing-history at observation date (summary re-derived under tool v1.1: `BSP-BKBN-ASN-PND-2026-10-20_ANALYST-IPORIGIN-summary-REDERIVED-v1.1.md`) | Level 4/5 — RDAP + BGP (validates sandbox resolutions) |
| 2026-10-20 | Origin check, run `IPORIGIN-20261020-161401Z` — `148.17.131.206`: ARIN RDAP + RIPEstat routing-history on `148.16.0.0/12`, 2026-02-06..12 (no announcement) | Level 4/5 — RDAP + BGP (validates sandbox resolution) |
| 2026-06-18 | `SNAP-BASELINE-20260618.md` | Level 5 — BGP/Prefix (change-detection baseline, includes AS6128 cross-reference) |
| 2026-08-25 | `bgp_neighbors_AS7046_20260505_<time>.txt` — RIPEstat `asn-neighbours`, window matched to AS7015 reference pull | Level 5 — BGP/Prefix (upstream-neighbor identity; basis for 4.3 reclassification) |
| 2026-08-25 | `rpki-validation_AS7046_<block>_20260825.txt` — 3 of 5 blocks checked (CFTC-NETWORK, DOLNET, WIRE-V6), all `status: unknown` | Level 4/5 — RPKI validation (indeterminate; TERRENAP-V6 and CMMS-IPV6 pending) |

### 8.1c Summarized Evidence — Non-Load-Bearing ASNs

The following ASNs are cleared/stable with no open questions; most are not individually
discussed in the narrative beyond their appearance in Table 4.1 (Section 4.2) or as baseline,
comparison, or control entries. Full per-file evidence tables have been condensed to one row
each; raw filenames and per-file hashes remain in `SHADOW_MARKET_FILE_HASHES.txt` regardless
of this summarization.

| ASN | Entity | Status | Case ref | Files | Role / Note |
|---|---|---|---|---|---|
| AS209 | CenturyLink/Lumen — Qwest/Embarq successor | LEGITIMATE_SUCCESSOR | CASE-007 | 4 | Baseline |
| AS701 | UUNET / Verizon Business — MCI successor | LEGITIMATE_SUCCESSOR | CASE-005 | 10 | Comparison/control (paired run with AS3549). *Handoff reference table flags a "CISA correction UPDATE-003" tie for this ASN — not present in this paper's draft text or in `SHADOW_MARKET_FILE_HASHES.txt`. Unverified; flagged for analyst confirmation, not asserted here.* |
| AS702 | UUNET-AS702 / Verizon Business legacy | LEGITIMATE_SUCCESSOR | CASE-005 | 2 | Comparison/control |
| AS2686 | ATGS-MMD-AS — AT&T Enterprises LLC | MISATTRIBUTION → LEGITIMATE_SUCCESSOR | CASE-007 | 1 | Comparison/control; prior working assumption (Sprint-FL/Embarq) corrected via RDAP+RIPEstat |
| AS3549 | Lumen / Level 3 — Global Crossing successor | LEGITIMATE_SUCCESSOR | CASE-004 | 10 | Paired run with AS701. *Same unverified UPDATE-003 reference as AS701 above — see note.* |
| AS5650 | FRONTIER-FRTR — Frontier Communications | MISATTRIBUTION | CASE-007 | 1 | Comparison/control; prior working assumption (Embarq Corp) corrected |
| AS6128 | Cablevision Systems (Altice retained) | RETENTION_ANOMALY | CASE-009 | 4 | Baseline |
| AS6478 | TCI/@Home (collapsed 2001, properly retired) | CLEAN | CASE-003 | 4 | Baseline |
| AS7132 | SBIS-AS / SBC Internet Services / Ameritech backbone | CLEAN | CASE-006 | 1 | Baseline |
| AS7922 | COMCAST-7922 (post-TCI production ASN) | CLEAN | CASE-002/003 | 3 | Baseline |
| AS8069 | Microsoft Corp | **MISATTRIBUTION** | CASE-006 | 7 | Cited in Table 4.1 (Section 4.2) as an H0-held resolution. **Phase history:** first tracked 2026-05-03 (`status: UNKNOWN`, `prefix_count: 770`); flagged `OWNERSHIP_ANOMALY` at the 2026-05-05 baseline, before that day's own ARIN RDAP check confirmed continuous Microsoft ownership since 1997 (block `MICROSOFT-CORP-MSN-AS-BLOCK`, AS8068–8075) with no Ameritech connection anywhere in the registration record — the flag was simply never revisited after the check that would have cleared it. This investigation's own status field already read `MISATTRIBUTION` by 2026-05-08. Independently re-confirmed 2026-08-27: ARIN block history rechecked, and a live routing spot-check across both ARIN-region (Azure, registrant `MSFT`) and RIPE-region (`MICROSOFT-MAINT`, named technical/abuse contacts) space came back clean in both regions. Prefix count grew linearly and unremarkably across every available snapshot (770 on 05-03 and 05-06, 772 on 05-08, 797 on 08-27) — ordinary growth for an actively operated hyperscale network. A separate tracking file, `ZOMBIE-ASN-REGISTRY.db`, briefly carried an `ACTIVE_MONITOR` label (dated 2026-05-12) that never appeared in `asn_source.json`'s documented schema — noted for chain-of-custody completeness, then set aside as an artifact of a less authoritative source rather than a competing finding. All queries saved as `ASN8069-MSN-output.txt`, hashed and logged in `SHADOW_MARKET_FILE_HASHES.txt`. |
| AS10796 | TWC-10796-MIDWEST (Charter retained, clean) | CLEAN | CASE-008 | 2 | Baseline |
| AS11426 | TWC-11426-CAROLINAS (Charter dual-ASN retention) | RETENTION_ANOMALY | CASE-001 | 3 | Baseline |
| AS14905 | CENTURYLINK-LEGACY-EMBARQ-VACHVL | LEGITIMATE_SUCCESSOR | CASE-007 | 1 | Comparison/control |
| AS20115 | Charter/Spectrum (production ASN) | CLEAN | CASE-001 | 1 | Baseline |
| AS33363 | BHN-33363 — attribution conflict (Adelphia vs. BHN) | PENDING_VERIFICATION → RETENTION_ANOMALY (confirmed 2026-05-07) | CASE-002 | 6 | Corrected, not cited in Section 4. Live recheck (2026-07-15): registrant/status unchanged; prefix count 494→436 (12% decline since baseline), cause open — no baseline total-IP figure on file to distinguish genuine shrinkage from routine aggregation. Logged CHG_DETECTED, not resolved either direction. |
| AS36727 | Insight Communications (post-acquisition clean) | CLEAN | CASE-008 | 3 | Baseline |
| AS54396 | Nuance Communications (small ASN, misattributed to Altice's cable ASN) | CLEAN → MISATTRIBUTION | CASE-009 | 1 | Corrected, not cited in Section 4. ARIN name is NUANCE-MOBILITY, 1 active prefix; AS6128 remains Altice's actual cable ASN for CASE-009. |

**Subtotal, summarized ASNs:** 18 ASNs, 64 evidence files.

### 8.2 Multi-ASN / Batch Evidence

*Cull review: reviewed during the 2026-07-29 evidence cull and kept as-is — already condensed to type/count/date-range on a prior pass; no further trimming warranted.*

Files not attributable to a single ASN — BGP watchlist monitor runs, batch DNS/pDNS sweeps, and multi-ASN RDAP/registration analyses. Cross-referenced under each relevant ASN above where applicable (e.g., the AS701/AS3549 RDAP analysis and the AS7015/AS8069 synthesis document each appear once here in aggregate and once under their respective ASN sections above). Summarized by type rather than listed individually; raw filenames and per-file hashes remain in `SHADOW_MARKET_FILE_HASHES.txt`.

| Type of Data Run | Number of Runs | Date Range |
|---|---|---|
| BGP watchlist monitor (`zombie_report`) | 42 | 2026-05-03 – 2026-05-20 |
| DNS/PTR check (`dns_check_batch`) | 12 | 2026-05-03 – 2026-05-04 |
| pDNS run log (`pdns_run`) | 11 | 2026-05-08 – 2026-05-09 |
| pDNS summary (`pdns_summary`) | 11 | 2026-05-08 – 2026-05-09 |
| RDAP/WHOIS (multi-ASN) | 6 | 2026-05-05 – 2026-05-06 |
| Procedural/command log | 4 (incl. `5-4-26-zombie-hunter-TerminalOutput.txt`, renamed from `Terminal Saved Output.txt`; `terminal-may5.txt`) | 2026-05-04 – 2026-05-05 |
| Other (incl. `setiii-rdap-arin.txt`) | 3 | 2026-05-03 – 2026-05-06 |
| Analyst synthesis, multi-ASN (`BLOCK 3-4`) | 1 | 2026-05-05 |
| BGP/Prefix, multi-ASN | 1 | 2026-05-05 |
| **Total, batch/multi-ASN evidence** | **91** | **2026-05-03 – 2026-05-20** |

### 8.3 Supporting Case Documents (Session-Provided, Not Per-ASN Evidence)

Working documents used to reconcile the evidence base and resolve the AS6181/AS2686 corrections. Retained for chain-of-custody completeness; not attributable to a single ASN.

| Date | File | Role |
|---|---|---|
| 2026-05-02 | `CISA-SUPPLEMENTAL-ZOMBIE-BGP-2026-05-02.txt` | The actual filed CISA supplemental report. Confirmed AS6181 was never included in this filing (swept for "6181", "AS702", "5650", "14905" — no genuine matches). |
| 2026-05-02 | `phase_a_candidates_20260502_011511.csv` | Phase A national survey scoring output; source of the original (later corrected) AS6181/Insight zombie-BGP flag. |
| 2026-05-08 | `PDNS-BATCH-QUEUE.txt` | Batch run plan confirming AS702/AS2686/AS5650/AS14905 were planned, in-scope VRF#26-04-TPWXX candidates (Batches C–E), not cross-case artifacts. |
| 2026-05-07 to 2026-05-19 | `BACKBONE-INVESTIGATION-LOG-v2.md` | Working investigation log; source for registry expansion (I-027, 20→23 ASNs) and the AS7015 post-05-19 status question flagged in the AS7015 entry above. |


---

## Appendix A. The Hunt: Method and the bybanking.com Trace

This appendix documents the hunting method behind the finding in Sections 4.3 and 5.3, in enough detail for another researcher to repeat it, and sets out how the question left open in Section 6.3 will be pursued. It adds no evidence: every item cited here is already in Section 8, and the confidence tiers, validation levels and designation gate are the ones defined in Sections 2.4, 3.2–3.6.

### A.1 Why hunt a flagged candidate

The validation pipeline (Section 3.3) exists to decide whether an ASN's routing is anomalous. Hunting asks a different question of the same candidate: what is actually living in the address space it announces? The two are deliberately kept separate. A hunt can produce a usable result even when the candidate's own disposition later resolves to the null hypothesis — which is what happened with AS7046 (Section 4.3). The flag selects where to look; it is not a claim about what will be found.

### A.2 The working loop

Every data check in this investigation follows the same eight steps, formalized 2026-08-17 (research log I-073):

| Step | Action |
|---|---|
| 1 | Run the check (one documented command or script) |
| 2 | Document the result as returned |
| 3 | Log it, cross-referenced to every prior entry for the same object |
| 4 | Cross-check against those prior entries |
| 5 | Assign a validation flag and confidence tier |
| 6 | Stop, and explicitly consider the next check rather than continuing automatically |
| 7 | Write down what that next check would be, and which disputed claim it tests |
| 8 | Repeat |

Step 7 carries a rule learned during this paper's own review: before a result is treated as settling a finding, state which disputed claim the query tests, and confirm the result addresses that claim. A query can return an accurate answer to a different question (log supplement, P2-5).

### A.3 The hunting sequence

Each stage below is run in order. Each one narrows the question for the next and carries its own source tier (Src-R regulatory registry, Src-S analyst-acquired aggregator, per the acquisition standard).

| Stage | Question | Method | Source | Output |
|---|---|---|---|---|
| H1 Select | Which announced space should be examined? | A candidate ASN flagged by the validation pipeline; enumerate its announced prefixes | RIPEstat announced-prefixes (Src-S) | Prefix list |
| H2 Sample | Which addresses inside it carry names? | Sample addresses per prefix; query passive DNS for each | Robtex passive DNS (Src-S) | Hostname–address pairs, with last-seen time |
| H3 Confirm the space | Is the address really inside space this ASN announces? | Direct prefix-list check, independent of the pDNS tool's own sampling | RIPEstat (Src-S) | Confirmed or rejected association |
| H4 Characterize the name | What does the domain do across time? | Compare hostnames, subdomains and addresses across separate hunts | Repeated H2–H3 runs | Rotation pattern, or none |
| H5 Validate | Does an independent observation agree? | Sandbox DNS resolutions only; verdicts and scores not used (Section 3.7) | Third-party and analyst-submitted sandbox reports | Additional resolved addresses |
| H6 Place each address | Who held and who routed each address *when it was seen*? | Regional-registry record for the address, then routing history over the observation date ±3 days, counting only prefixes that cover the address | RIR RDAP (Src-R); RIPEstat routing-history (Src-S) | Registrant and origin ASN at observation |
| H7 Gate | Does anything justify a label? | Designation gate: null explanation first, named evidentiary bar, flat description if not cleared (Section 2.4) | Research log | Label, or plain description |

Two standing rules apply throughout. Registry lookups start from the IANA RDAP bootstrap, so each address is queried at the registry responsible for it; ARIN answers for out-of-region space with a referral placeholder that is easy to mistake for a finding. And every result is placed at its observation date, not today: an address announced by one network in July can be announced by another, or by none, in October.

### A.4 Worked trace: bybanking.com

| Date | Stage | Observation | Source (Section 8.1b) |
|---|---|---|---|
| 2026-05-19 | H1 | AS7046 enters the investigation through a monitoring thread whose premise was later retracted (Section 4.4) | Research log I-032 |
| 2026-06-16 | H2 | First passive-DNS run on AS7046: 20 of 219 prefixes and 100 addresses sampled, one record returned — `9ve2e267.bybanking.com` with `161.162.17.104`, last seen 2026-06-16T20:08:25Z | I-047; `BIV-ANO-2026-06-16_AS7046-PDNS-BYBANKING.md` |
| 2026-06-16 | — | Only after the hit: a third-party sandbox report from 2026-02-09 located by search. The discovery did not depend on it | 8.1b discovery note |
| 2026-07-15 | H2–H3 | Second run: `ns-5whj.bybanking.com` with `198.57.13.170`, a different subdomain, address and /24. Both /24s confirmed as announced by AS7046 | 8.1b |
| 2026-07-16 | — | Finding transmitted via IC3 (30 days after discovery; see the reporting-delay note) | 8.1b |
| 2026-07-25 | H5 | Sandbox resolutions to `145.74.110.172` and `123.150.3.39` | 8.1b, validation only |
| 2026-07-26 | H3 | `123.150.3.39` confirmed outside AS7046's announced space | 8.1b |
| 2026-08-25 | — | AS7046 itself reclassified as normally operated; the domain finding retained as an impact finding (Section 4.3) | 8.1b |
| 2026-10-20 | H6 | `123.150.3.39` → AS17638 (China Telecom, Tianjin); `145.74.110.172` → AS1103 (SURF, a university's block); `148.17.131.206` (2026-02-09) → DoD-registered space announced by no network | Runs `IPORIGIN-20261020-050622Z`, `IPORIGIN-20261020-161401Z` |
| 2026-10-20 | H7 | DoD-space resolution: null explanation (a record pointing at an unreachable address) not displaced; bar not cleared; described flatly | Research log I-090 |

**Result of the hunt.** A domain characterized as malicious on its infrastructure behavior — rotation across subdomains, address blocks and unrelated networks in North America, Europe and Asia, including at least one resolution to an address no network routed — was found inside a normally operated carrier's customer-aggregation space. That is the finding reported in Section 5.3.

**Yield, stated honestly.** One record from 100 sampled addresses, in under a tenth of the ASN's prefixes. The sample was enough to find something; it is not enough to say nothing else is there. A full-coverage pass over all of AS7046's announced space has not been run.

### A.5 What the hunt does not establish

Who operates the domain. What traffic, if any, its addresses carried. Why it surfaced in this ASN's customer space. Why it resolved, in February, to unannounced space. Whether any registrant of any address involved knew of it. The passive-DNS records carry a last-seen time only, so how long each association was live is unknown (Section 6.3). Whether the H2 records are reverse (PTR) records or forward records indexed by address affects who could have created them; the raw files' record-type field answers that, and the paper's wording holds either way.

### A.6 Lessons the hunt surfaced

| Lesson | Where it showed up | Standing rule |
|---|---|---|
| Check the instrument before the network | A "dark window" that was a monitoring failure, shared with a clean control ASN (Section 4.4) | When a watched object changes, check the controls for the same window first |
| A null field needs a base rate | Empty `originas` on every block, flagged and control alike (Section 3.4) | Test any registry field against the control set before treating it as a signal |
| Place results at the observation date | Three sandbox addresses, three different networks at three different times | Query history over the observation window, never today's state alone |
| Count only what covers the address | An early tool version counted every origin seen in a surrounding /16 | Origin claims use covering prefixes only; the correction is logged in I-090 |
| Ask the right registry | ARIN referral placeholders for AFRINIC and RIPE space | Select the registry from the IANA bootstrap |
| Sandbox output answers a different question | Verdicts shifted as the investigation resubmitted | Sandbox DNS resolutions validate; verdicts are not evidence (Section 3.7) |

### A.7 Continuing the hunt: longitudinal observation

Section 6.3's open question — why a malicious domain resurfaced twice in the same carrier's space — cannot be answered from snapshots. It is being pursued as a standing longitudinal study (protocol `BSP-BKBN-ASN-longitudinal-protocol.md`), designed with three constraints this paper's review made necessary:

- **Two variables, never merged.** Occupancy (what is announced, by whom, seen by how many collectors) and stewardship (registry records, ROAs, contact validation) are measured separately. Quiet routing alone is never read as remediation.
- **Cause-agnostic.** The study records what the address space does over time. It does not track or correlate external events; a disruption enters the record only as an observed change in the space.
- **Controls in every run.** All 24 ASNs of the evidence base are observed together, so a change seen on a control in the same window is treated as an instrument event before it is treated as a finding.

Each observation window is one acquisition run, by the analyst, with raw responses hashed at capture. A change between windows triggers a denser schedule and a second routing collector before any state is recorded. The stewardship question this paper could not answer — does the gap close, or does the space get reoccupied? — becomes a measured outcome rather than an inference.

### A.8 Tools

| Tool | Version | SHA-256 | Role |
|---|---|---|---|
| `asn_pdns_puller.py` | as used 2026-06-16 and 2026-07-15 | not recorded — its outputs are hashed, the tool itself was not; to be hashed and the gap noted | H1–H2 prefix enumeration and passive DNS |
| `bkbn_ip_origin_pull.py` | 1.2 (1.1 for run `…161401Z`; 1.0 for run `…050622Z`, re-derived under 1.1) | `9d9028c7…a8c4` | H6 registry and origin-at-observation |
| `bkbn_longitudinal_pull.py` | 1.3 | `86f50095…e9dd` | A.7 observation windows |

All acquisitions use public, read-only registry and aggregator endpoints. None touches the domain's own infrastructure.

---

*VRF#26-04-TPWXX | Backwater Forensics | Lu Anne Gammage (Esposito), MS Digital Forensic Science | Revised 2026-10-20*
