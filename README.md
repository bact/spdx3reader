---
SPDX-FileCopyrightText: 2025-present Arthit Suriyawongkul <suriyawa@tcd.ie>
SPDX-FileType: DOCUMENTATION
SPDX-License-Identifier: Apache-2.0
---

# SPDX 3 Reader

SBOM compliance experimentation for GSoC 2025.

Read SPDX 3 JSON file, get SPDX 3 document as Python objects,
and look for NTIA minimum elements.

```shell
pip install -e .
```

To test print NTIA minimum elements and all relationships:

```shell
python scripts/spdx3read.py --print --rel tests/data/dataset-example01.json
```

The current code can check all the existence of all minimum elements
but not yet the relationships (like licenses).

To be integrated into `ntia-conformance-checker`.

Note: see the SPDX 3.0 - NTIA Minimum Elements mapping from this
[design document](https://docs.google.com/document/d/1pueRxlxoM9n1eG9g6AihjLvybEBTd77m22mRYBQltpg/edit?tab=t.0#heading=h.qtqmj6afdw8r).
