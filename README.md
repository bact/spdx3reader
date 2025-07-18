---
SPDX-FileCopyrightText: 2025-present Arthit Suriyawongkul <suriyawa@tcd.ie>
SPDX-FileType: DOCUMENTATION
SPDX-License-Identifier: Apache-2.0
---

# SPDX 3 Reader

SBOM compliance experimentation for GSoC 2025.

Read SPDX 3 JSON file, get SPDX 3 document as Python objects,
and look for NTIA minimum elements.

To test print NTIA minimum elements and all relationships:

```shell
python src/spdx3reader/spdx3read.py --print --rel tests/data/dataset-example01.json
```

The current code can check all the existence of all minimum elements
but not yet the relationships (like licenses).

To be integrated into `ntia-conformance-checker`.
