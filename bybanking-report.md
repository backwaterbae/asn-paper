# bybanking.com: Domain Follow-up
### Companion note to the backbone-addressing paper
**Backwater Forensics | 2026-10-24 | interim (one item open until late November 2026)**

Relates to: L. A. Gammage (Esposito), *How Unassigned Addressing Created a New Attack Vector: An Analysis of Dormant Autonomous System Exploitation in Backbone Internet Infrastructure*, draft 2026-08-25, §§5.3 and 8.1b.

---

## Why this note exists

The paper reports that bybanking.com resolved into two AS7046-announced customer blocks, two months apart (§5.3, §8.1b), and that the finding was reported to authorities in July 2026. The paper's question was about the ASN. This note asks the follow-up question about the **domain**: how it was registered, how its DNS worked, what certificates exist for it, and how every address it resolved to was routed.

Organisations whose address space the domain resolved into are **not named** here. As explained below, a DNS answer does not show that those networks hosted anything, and naming them next to a malicious-domain report invites exactly that misreading.

## Method

- **Primary sources first:**
  - .com registry RDAP (Verisign)
  - registrar RDAP
  - RIR RDAP (ARIN, APNIC)
  - RIPEstat prefix-overview and routing history
- **Then aggregators:**
  - Certificate Transparency logs (via crt.sh)
  - a commercial WHOIS-history service (62 captures, 2013–2026)
- **Passive and read-only throughout.** No contact with the domain's operator, no probing of its infrastructure, and nothing submitted to URL scanners.
- **Custody.** Every file was SHA-256 hashed at acquisition and is held with its chain-of-custody record by Backwater Forensics.
- **Dates.** Collection ran 2026-10-06 to 2026-10-15.

## Findings

### 1. The name has been dropped and re-registered about seven times since 2013

| Lifecycle | Began | DNS used |
|---|---|---|
| 1 | Sep 2013 | Registrar / provider DNS |
| 2 | Aug 2015 | Provider DNS, ending on the registrar's expiry nameservers (2020) |
| 3 | Nov 2020 | Provider DNS, ending on "domain has expired" nameservers (2021) |
| 4 | Jan 2022 | Provider DNS |
| 5 | Apr 2023 | Provider DNS |
| 6 | Jun 2024 | Provider DNS; parked on an aftermarket sales platform by Aug 2025 |
| 7 | **Oct 2025** | **Self-run:** in-zone nameservers `ns1` / `ns2.bybanking.com` |

Each lifecycle has a new creation date, so the name lapsed and was re-registered each time, across seven different registrars. The current registration is privacy-protected. **Only the current lifecycle runs its own nameservers**, and it has done so from its first capture.

### 2. Both nameservers are one cloud server

The registry's host records for `ns1` and `ns2.bybanking.com` carry the same single IPv4 address. That address is registered to a major cloud-hosting provider: one virtual server, with no redundancy. This is the only host in the case that the domain's operator demonstrably runs.

### 3. The answer addresses belong to unrelated organisations, not hosting providers

The table covers every address the paper (§8.1b) recorded for the domain, looked up at its regional internet registry and in BGP routing history.

| Observation (from the paper) | Address registered to | Routing |
|---|---|---|
| Feb 2026 sandbox: apex record | A **US government allocation** | Covering prefix **withdrawn from global BGP in Feb 2025** and unannounced since, so it had no public route when the domain pointed at it |
| Jun 2026 pDNS: random-label subdomain | A US corporation (end-user /24) | Originated by AS7046 continuously, Oct 2025 – Oct 2026 |
| Jul 2026 pDNS: `ns-` label | A second, unrelated US corporation (end-user allocation) | Originated by AS7046 continuously over the same period |
| Jul 2026: China-resolving address | A Chinese incumbent carrier | Continuously originated by that carrier |
| Feb 2026 sandbox: Hong Kong contact | A Hong Kong transit carrier | A second origin AS appears on 2026-02-24, two weeks *after* the sighting. Not linked to the domain by timing; recorded for the backbone research |

None of the addresses is registered to a hosting provider.

**How to read this.** The domain answered its own DNS (findings 1–2), and whoever controls an authoritative nameserver can publish any address at all. These records therefore show what the domain **claimed**, not where anything was hosted. There are three explanations, and none has been tested:

1. **Decoy or collateral records.** The answers point at large-organisation or government space, which makes blocking costly or makes the domain look benign. This fits the random-label subdomains and the 5-second TTL the paper records.
2. **Compromised hosts** inside those organisations. The organisations would then be victims.
3. **Passive-DNS or sandbox artefacts.**

### 4. No public TLS since the current registration

- **Before October 2025**, CT logs show certificates for the name across the earlier lifecycles:
  - December 2024: certificates shared with an unrelated domain (same server at the time);
  - February 2025: a paid certificate;
  - July 2025: a burst of scanner-probe hostnames (`staging`, `dev`, `backup`, …) issued minutes apart. That is the signature of wildcard DNS combined with on-demand certificate issuance.
- **Since the current registration (October 2025)**, no publicly trusted certificate has been logged for any name under the domain, including the subdomains in the paper.

### 5. Status after the report

- **No hold.** No registry or registrar hold or suspension status appeared at any point between the July 2026 report and the registration's expiry in October 2026.
- **Delegation change.** On the day after expiry, the registry delegation moved from the operator's nameserver to the registrar's default nameservers. Since then, resolvers no longer reach the operator's server for this domain.
- **Renewal not settled.** The registry shows the standard .com automatic one-year renewal. As of 15 October 2026, the registrar had not recorded a renewal. Whether the holder renews, or the name moves to redemption and deletion, settles at the end of the 45-day grace period, around **22 November 2026**. This note will get an addendum then.

## Working hypothesis (not a finding)

The pattern fits a **DNS command channel**. Data would travel in the query labels (`9ve2e267.`, `ns-5whj.`) to a nameserver the operator runs. The A-record answers would then be encoded data rather than hosts, which would explain why they land in arbitrary, even unrouted, address space and carry a 5-second TTL (every query reaches the server).

| Link | Status |
|---|---|
| 1. The only real host is the nameserver | **Supported** (findings 1–2) |
| 2. Many unique random labels with differing answers | Untested: needs passive-DNS volume data |
| 3. Independent malware / IOC references | Untested |

The ordinary explanation was tested first: traffic monetisation or parking with wildcard DNS. It is **weakened, not refuted**. A self-run VPS is not a parking provider, and monetisation normally needs HTTPS serving, which has been absent since October 2025.

## Refinement to the paper

- **§8.1b** describes the two AS7046-announced blocks as "hosting blocks." On this evidence they are better described as **resolution targets**: AS7046 announces these customers' blocks, and nothing shows that AS7046 or the customers hosted the domain. This is consistent with the paper's own §4.3 reclassification of AS7046.
- **The Feb 2026 apex answer** pointed into unrouted government space. This is relevant to the paper's dormant-space discussion as an observation; it is not a stewardship-gap finding.
- **The paper's AS7046 conclusions are unaffected.**

## What this note does not establish

- That bybanking.com is malicious beyond the single third-party sandbox report (score 45/100) the paper relies on. No independent malware or IOC reference has been obtained yet.
- Who operates the domain. The registrant of record is a privacy service.
- That any organisation whose address space the domain resolved into hosted, operated, or was compromised in connection with it.
- Why delegation changed after expiry, or whether the registration will survive the grace period.
- Whether any takedown action has occurred. None is visible at registry or registrar level.

---
*Backwater Forensics | 2026-10-24 | interim, addendum expected after 2026-11-22*
