# How Unassigned Addressing Created a New Attack Vector
**Read: https://github.com/backwaterfx/asn-paper/blob/main/asn-vector-thesis.md

**An Analysis of Dormant Autonomous System Exploitation in Backbone Internet Infrastructure**

L. A. Gammage, MS Digital Forensic Science · Backwater Forensics
Research Series: Infrastructure Security · Revised 2026-10-20

---

Autonomous System numbers that go dormant after a carrier acquisition, bankruptcy or internal retirement are usually treated as bookkeeping left uncorrected. This paper argues that dormant ASN space with no accountable operator is address space no one is positioned to notice or contest unauthorized use of, and that the gap is exploitable. It tests that claim against a 24-ASN evidence base under a null-hypothesis-first standard.

| | |
|---|---|
| **Null hypothesis did real work** | 8 ASNs cleared against the administrative-lag null for the 2 that rejected it (Section 4.2) |
| **Cross-ASN signature** | One confirmed instance (AS11427) and one lead pending a block-level registry check (AS7029) (Section 4.1) |
| **Exposure isn't confined to dormant space** | A normally operated carrier ASN (AS7046) still carried a malicious domain in its customer space (Sections 4.3, 5.3) |
| **Instrument before network** | An apparent routing event traced to a monitoring failure shared with a clean control, then corrected in public (Section 4.4) |
| **The hunt, documented** | Method and full trace for the bybanking.com finding (Appendix A) |

## Contents

| Path | What it is |
|---|---|
| `paper/…-2026-10-20.pdf` | The paper (30 pages) |
| `paper/…-2026-10-20.md` | The same paper in Markdown, the source the PDF and web page are built from |
| `web/index.html` | Self-contained web page: summary, full text, citation. Replace `PDF_LINK_HERE` and `GITHUB_LINK_HERE` before hosting |
| `tools/` | The acquisition tools cited in Appendix A, with their own [README](tools/README.md) |
| `build/` | Scripts that render the Markdown to the PDF and the web page |
| `SHA256SUMS` | Checksums for every file in this repository |

## Verify

```bash
shasum -a 256 -c SHA256SUMS
```

## Rebuild the PDF and web page

Requires Python 3 with `markdown` and `playwright` (Chromium), plus the Carlito and Liberation Mono fonts for a faithful PDF.

```bash
python3 build/build_pdf.py  "$PWD/paper/BSP-BKBN-ASN-BACKBONE-ADDRESSING-PAPER-2026-10-20.md" "$PWD/paper.html" "$PWD/paper.pdf"
python3 build/build_html.py paper/BSP-BKBN-ASN-BACKBONE-ADDRESSING-PAPER-2026-10-20.md web/index.html
```

## What is not here

Raw evidence files, case logs and internal working documents are not published. Section 8 of the paper lists every evidence file with its role; per-file hashes are held in the investigation's own custody records.

## Cite

> Gammage (Esposito), L. A. (2026). *How unassigned addressing created a new attack vector: An analysis of dormant Autonomous System exploitation in backbone internet infrastructure* (Revised 2026-10-20). Backwater Forensics.

Machine-readable metadata is in `CITATION.cff`; GitHub shows a "Cite this repository" button from it.

## License

- **Paper** (`paper/`, `web/`): [Creative Commons Attribution 4.0 International](https://creativecommons.org/licenses/by/4.0/). See `LICENSE-PAPER.md`.
- **Code** (`tools/`, `build/`): MIT. See `LICENSE`.

---

BACKWATER FORENSICS · backwaterforensics.com · Research Series: Infrastructure Security

All carrier and ASN data sourced from public record (ARIN, RDAP, RIPEstat, FCC, SEC). Actor-agnostic throughout. Infrastructure conditions only — no exploit methods disclosed.
