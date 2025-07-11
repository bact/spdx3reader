# SPDX-FileCopyrightText: 2025-present Arthit Suriyawongkul <suriyawa@tcd.ie>
# SPDX-FileType: SOURCE
# SPDX-License-Identifier: Apache-2.0

import argparse
import json

from spdx_python_model import v3_0_1 as spdx3
from spdx_python_model import VERSION
from spdx_python_model import bindings


def read_json_file(filepath: str):
    with open(filepath, "r", encoding="utf-8") as f:
        return json.load(f)


def deserialize_spdx_json_file(filepath: str) -> spdx3.SHACLObjectSet:
    object_set = spdx3.SHACLObjectSet()
    with open(filepath, "r", encoding="utf-8") as f:
        spdx3.JSONLDDeserializer().read(f, object_set)
        return object_set


# def json_to_spdx_graph(json_data) -> list[spdx3.SHACLObject]:
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
        "-D", "--dump", action="store_true", help="Print the JSON content"
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

    if args.dump:
        json_data = read_json_file(args.filepath)
        print(json.dumps(json_data, indent=2))

    spdx_object_set = deserialize_spdx_json_file(args.filepath)
    if args.tree:
        print("SPDX Object Tree:")
        spdx3.print_tree(spdx_object_set.objects)
        print(len(spdx_object_set.objects), "SPDX objects found.")

    spdx_documents = list(spdx_object_set.obj_by_type["SpdxDocument"])
    if len(spdx_documents) != 1:
        print(
            "Warning: There should be exactly one SpdxDocument object in an SPDX 3 JSON file."
        )
        print(f"Found: {len(spdx_documents)}")
    else:
        print(spdx_documents)
        doc = spdx_documents[0][1]
        print("SPDX Spec Version:", doc.creationInfo.specVersion)
        root_element = doc.rootElement[0]
        print("Root SPDX Object ID:", root_element.spdxId)

    if args.rel:
        print("Relationships:")
        relationships = spdx_object_set.obj_by_type["Relationship"]
        print(len(relationships), "relationships found.")
        print()
        for rel in relationships:
            from_ = getattr(rel[1], "from_")
            to = getattr(rel[1], "to")
            rel_type = getattr(rel[1], "relationshipType")
            print(from_)
            print(rel_type.split("/")[-1])  # Print only the term, omit the IRI prefix
            for o in to:
                print(o)
            print()

class NTIAMinimumElement:
    ntia_min_fields = {
        "author_name": "Author Name",
        "supplier_name": "Supplier Name",
        "component_name": "Component Name",
        "version_string": "Version String",
        "component_hash": "Component Hash",
        "unique_identifier": "Unique Identifier",
        "relationship": "Relationship",
        "timestamp": "Timestamp",
    }

    def __init__(self):
        self.ntia_min = {k: None for k in self.ntia_min_fields}

    def __str__(self):
        lines = []
        for k, v in self.ntia_min.items():
            lines.append(f"{NTIAMinimumElement.ntia_min_fields[k]}: {v}")
        return "\n".join(lines)

if __name__ == "__main__":
    print(f"SPDX Python Model Version: {VERSION}")
    print("Available bindings in spdx_python_model:")
    for name in dir(bindings):
        if not name.startswith("__"):
            print(name)
    main()

    ntia_min = NTIAMinimumElement()
    print(ntia_min)
