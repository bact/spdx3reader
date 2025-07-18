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

from compliance_info import get_ntia_minimum_element


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
        from_ = getattr(rel, "from_")
        to = getattr(rel, "to")
        rel_type = getattr(rel, "relationshipType")
        print(from_)
        print(rel_type.split("/")[-1])  # Print only the term, omit the IRI prefix
        for o in to:
            print(o)
        print()


# def json_to_spdx_graph(json_data) -> List[spdx3.SHACLObject]:
#     """
#     Convert JSON data to an SPDX 3.0.1 document.
#     """
#     spdx3_classes = {
#         name: cls
#         for name, cls in vars(spdx3).items()
#         if inspect.isclass(cls) and cls.__module__ == spdx3.__name__
#     }

#     json_graph_data = json_data.get("@graph", [])
#     for entry in json_graph_data:
#         type_name = entry.get("type")
#         if not type_name:
#             continue
#         cls = spdx3_classes.get(type_name)
#         if cls is None:
#             continue  # Unknown type, skip
#         obj = cls()
#         for k, v in entry.items():
#             if k != "type":
#                 obj[k] = v
#         graph.append(obj)

#     return graph


def main():
    parser = argparse.ArgumentParser(description="Read and print an SPDX 3 JSON file.")
    parser.add_argument("filepath", help="Path to the SPDX 3 JSON file")
    parser.add_argument(
        "-V", "--version", action="store_true", help="Print version information"
    )
    parser.add_argument(
        "-P",
        "--print",
        action="store_true",
        help="Print the minimum elements/baseline attributes",
    )
    parser.add_argument(
        "-J", "--json-dump", action="store_true", help="Print the JSON content"
    )
    parser.add_argument(
        "-T", "--tree", action="store_true", help="Print the SPDX object tree"
    )
    parser.add_argument(
        "-R",
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

    ntia = get_ntia_minimum_element(spdx_object_set)

    if args.print:
        print("NTIA Minimum Element:")
        print(ntia)

    if not ntia.is_compliant():
        print("Not compliant with NTIA Minimum Element requirements.")
        sys.exit(1)

    print("Compliant with NTIA Minimum Element requirements.")


if __name__ == "__main__":
    main()
