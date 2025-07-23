---
SPDX-FileCopyrightText: 2025-present Arthit Suriyawongkul <suriyawa@tcd.ie>
SPDX-FileType: DOCUMENTATION
SPDX-License-Identifier: Apache-2.0
---

# SPDX 3 Reader

SBOM compliance experimentation for GSoC 2025.

Read SPDX 3 JSON file, get SPDX 3 document as Python objects,
and look for NTIA minimum elements.

To install the library:

```shell
pip install -e .
```

To print all relationships in an SPDX 3 JSON file:

```shell
python scripts/spdx3read.py --rel tests/data/dataset-example01.json
```

Output will look like this:

```text
Relationships:

┏━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┅
┃ dataset_DatasetPackage
┃  - name: Our World in Data CO2 and Greenhouse Gas Emissions dataset
┃  - spdxId: https://spdx.org/spdxdocs/DatasetPackage1-035470d9-3ede-4952-91c8-c2abb943c90b
┗━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┅
    │
  hasDeclaredLicense
    ↓
  ┏━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┅
  ┃ simplelicensing_LicenseExpression
  ┃  - name: None
  ┃  - spdxId: https://spdx.org/licenses/CC-BY-4.0
  ┗━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┅

┏━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┅
┃ dataset_DatasetPackage
┃  - name: Our World in Data CO2 and Greenhouse Gas Emissions dataset
┃  - spdxId: https://spdx.org/spdxdocs/DatasetPackage1-035470d9-3ede-4952-91c8-c2abb943c90b
┗━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┅
    │
  hasConcludedLicense
    ↓
  ┏━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┅
  ┃ simplelicensing_LicenseExpression
  ┃  - name: None
  ┃  - spdxId: https://spdx.org/licenses/CC-BY-4.0
  ┗━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┅

┏━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┅
┃ software_File
┃  - name: codebook.csv
┃  - spdxId: https://spdx.org/spdxdocs/File2-caf55baf-cd02-406a-b7ec-838842ca869f
┗━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┅
    │
  describes
    ↓
  ┏━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┅
  ┃ software_File
  ┃  - name: data.csv
  ┃  - spdxId: https://spdx.org/spdxdocs/File1-d029fccb-7ee9-42be-a445-5e2066db0de8
  ┗━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┅

┏━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┅
┃ dataset_DatasetPackage
┃  - name: Our World in Data CO2 and Greenhouse Gas Emissions dataset
┃  - spdxId: https://spdx.org/spdxdocs/DatasetPackage1-035470d9-3ede-4952-91c8-c2abb943c90b
┗━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┅
    │
  contains
    ↓
  ┏━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┅
  ┃ software_File
  ┃  - name: data.csv
  ┃  - spdxId: https://spdx.org/spdxdocs/File1-d029fccb-7ee9-42be-a445-5e2066db0de8
  ┗━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┅
  ┏━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┅
  ┃ software_File
  ┃  - name: codebook.csv
  ┃  - spdxId: https://spdx.org/spdxdocs/File2-caf55baf-cd02-406a-b7ec-838842ca869f
  ┗━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┅

4 relationships found.
Not compliant with FSCT Baseline Attribute requirements.
```

To print the baseline attributes:

```shell
python scripts/spdx3read.py --print tests/data/dataset-example01.json
```

Output will look like this:

```text
FSCTBaselineAttribute:
- SBOM Author Name: ['Arthit Suriyawongkul']
- SBOM Timestamp: 2024-05-31 00:00:00+00:00
- SBOM Type: ['analyzed']
- SBOM Primary Component: True
- Primary Component Name: Our World in Data CO2 and Greenhouse Gas Emissions dataset
- Primary Component Version String: 2024-04-15
- Primary Component Supplier Name: Our World in Data
- Primary Component Cryptographic Hash: [('sha1', '32657f0d033fc07a7420be36a6af9083c6a63489'), ('sha256', '434d75c84cf86456c16193dbc53beef31eb63f3387425882ddb2ef6acb9d472c')]
- Primary Component Unique Identifiers: [('spdxId', 'https://spdx.org/spdxdocs/DatasetPackage1-035470d9-3ede-4952-91c8-c2abb943c90b')]
- Primary Component Relationships: None
- Primary Component License: ['CC-BY-4.0']
- Primary Component Copyright Holder: Copyright Our World in Data
- All components have Name: True
- All components have Version String: True
- All components have Supplier Name: False
- All components have Cryptographic Hash: False
- All components have Unique Identifiers: True
- All components have Relationships: False
- All components have License: False
- All components have Copyright Holder: False
Not compliant with FSCT Baseline Attribute requirements.
```

The current code can check all the existence of all minimum elements/baseline attributes
but not yet the relationships (like licenses).

To be integrated into `ntia-conformance-checker`.

Note: see the SPDX 3.0 - NTIA Minimum Elements mapping from this
[design document](https://docs.google.com/document/d/1pueRxlxoM9n1eG9g6AihjLvybEBTd77m22mRYBQltpg/edit?tab=t.0#heading=h.qtqmj6afdw8r).
