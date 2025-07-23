# SPDX-FileCopyrightText: 2025-present Arthit Suriyawongkul <suriyawa@tcd.ie>
# SPDX-FileType: SOURCE
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

import argparse
import json
import sys

from typing import List

from spdx_python_model import VERSION, bindings
from spdx_python_model import v3_0_1 as spdx3

from spdx3reader.compliance import FSCTBaselineAttribute, load_compliance_info


def read_json_file(filepath: str):
    with open(filepath, encoding="utf-8") as f:
        return json.load(f)


def deserialize_spdx_json_file(filepath: str) -> spdx3.SHACLObjectSet:
    object_set = spdx3.SHACLObjectSet()
    with open(filepath, encoding="utf-8") as f:
        spdx3.JSONLDDeserializer().read(f, object_set)
        return object_set


def print_relationships(relationships: List[spdx3.Relationship]):
    for rel in relationships:
        from_ = getattr(
            rel, "from_"
        )  # spdx-python-model uses "from_" instead of "from" to avoid the Python keyword
        to = getattr(rel, "to")
        rel_type = getattr(rel, "relationshipType").split("/")[
            -1
        ]  # print only the type name, not the full URL

        print("┏" + "━" * 50 + "┅")
        print(f"┃ {from_.__class__.__name__}")
        print(f"┃  - name: {from_.name}")
        print(f"┃  - spdxId: {from_.spdxId}")
        print("┗" + "━" * 50 + "┅")

        print("    │")
        print(f"  {rel_type}")
        print("    ↓")

        for o in to:
            print("  ┏" + "━" * 50 + "┅")
            print(f"  ┃ {o.__class__.__name__}")
            print(f"  ┃  - name: {o.name}")
            print(f"  ┃  - spdxId: {o.spdxId}")
            print("  ┗" + "━" * 50 + "┅")

        print()


def main():
    parser = argparse.ArgumentParser(description="Read and print an SPDX 3 JSON file.")
    parser.add_argument("filepath", help="Path to the SPDX 3 JSON file")
    parser.add_argument(
        "-v", "--version", action="store_true", help="Print version information"
    )
    parser.add_argument(
        "-p",
        "--print",
        action="store_true",
        help="Print the minimum elements/baseline attributes",
    )
    parser.add_argument(
        "-j", "--json-dump", action="store_true", help="Print the JSON content"
    )
    parser.add_argument(
        "-t", "--tree", action="store_true", help="Print the SPDX object tree"
    )
    parser.add_argument(
        "-r",
        "--rel",
        action="store_true",
        help="Print all relationships in the SPDX file",
    )
    args = parser.parse_args()

    if args.version:
        print(f"SPDX Python Model Version: {VERSION}")
        print("Available bindings in spdx_python_model:")
        for name in dir(bindings):
            if not name.startswith("__"):
                print(name)

    if args.json_dump:
        json_data = read_json_file(args.filepath)
        print(json.dumps(json_data, indent=2))

    spdx_object_set = deserialize_spdx_json_file(args.filepath)

    if args.tree:
        print("SPDX Object Tree:")
        spdx3.print_tree(spdx_object_set.objects)
        print(len(spdx_object_set.objects), "SPDX objects found.")

    if args.rel:
        relationships: List[spdx3.Relationship] = list(
            spdx_object_set.foreach_type(spdx3.Relationship)
        )
        print("Relationships:")
        print()
        print_relationships(relationships)
        print(len(relationships), "relationships found.")

    # info_base = NTIAMinimumElement()
    info_base = FSCTBaselineAttribute()
    load_compliance_info(spdx_object_set, info_base)

    if args.print:
        print(info_base)

    if not info_base.is_compliant():
        print(f"Not compliant with {info_base.compliance_standard} requirements.")
        sys.exit(1)

    print(f"Compliant with {info_base.compliance_standard} requirements.")


if __name__ == "__main__":
    main()
