# Open-Source Compliance & Code Audit Report
# SPDX-License-Identifier: OGL-UK-3.0

**Repository:** `federator-certificate-manager`   
**Date of Last Audit:** `2026-03-24`   
**Reviewed By:** `Informed Solutions`   

---

## Overview
As part of NDTP’s commitment to open-source compliance and security best practices, this repository has undergone an audit using FOSSology and SPDX checks, with Copyleaks readiness assessed, to verify:

- All third-party components are properly licensed and attributed.
- No proprietary or restricted-license code has been included.
- No unintentional code duplication from external sources.
- All code follows NDTP’s dual-license model (Apache 2.0 for code, OGL-UK-3.0 for documentation).

---

## Tools Used for the Audit

| Tool | Purpose | Scan Date |
|------|---------|----------|
| FOSSology (`nomos`, `copyright`) | Open-source license and copyright scanning | `2026-03-24` |
| SPDX License Analysis (`rg` header sweep) | SPDX header detection and coverage checks | `2026-03-24` |
| Copyleaks | Duplicate/plagiarism detection | `2026-03-24 (blocked - credentials unavailable)` |
| Manual Review | Review of flagged licenses and compliance gaps | `2026-03-24` |

Evidence artifacts generated during this audit:
- `target/audit/fossology-nomos-clean.json`
- `target/audit/fossology-copyright-clean.json`
- `target/audit/THIRD-PARTY.txt`
- [docs/third-party-notices.md](docs/third-party-notices.md)

---

## License Compliance Check (FOSSology and SPDX)

### Third-Party Dependencies and Attribution

| Component | License | Attribution Required? | Compliance Verified? |
|-----------|---------|----------------------|----------------------|
| Maven runtime dependencies (`71` total) | Open-source licenses (primarily Apache-2.0, MIT, BSD, Bouncy Castle; includes some dual-license metadata such as EPL/LGPL and GPL+Classpath Exception options) | `Yes` | `Yes (see [third-party notices](docs/third-party-notices.md))` |

Issues Identified:
- Dual-license/copyleft indicators present in dependency metadata for:
  - `ch.qos.logback:logback-classic` (EPL-1.0 / LGPL)
  - `ch.qos.logback:logback-core` (EPL-1.0 / LGPL)
  - `jakarta.annotation:jakarta.annotation-api` (EPL-2.0 / GPL2+CPE)
- Action Taken: Dependencies were identified and documented for legal policy review; no proprietary license findings were detected.

Repository scan summary (FOSSology `nomos` over tracked files):
- Files scanned: `102`
- License hits: `Apache-2.0 (69)`, `OGL-UK-3.0 (2)`, `No_license_found (30)`, `UnclassifiedLicense (1: LICENSE.md)`
- Proprietary/restricted-license keyword hits in scan output: `0`

SPDX header coverage:
- Java files with SPDX header: `56/56`
- Source-like files with SPDX header (`Dockerfile`, `scripts/*.sh`, `src/**/*.java`, `pom.xml`, `mvnw`, `mvnw.cmd`, `Makefile`): `62/62`

All required attribution records for dependencies are present in [third-party-notices.md](docs/third-party-notices.md).

---

## Final Compliance Status

After running FOSSology and SPDX checks, this repository is:

- `Compliant`
- `Necessary actions taken for FOSSology/SPDX`

**Maintained by the National Digital Twin Programme (NDTP).**
