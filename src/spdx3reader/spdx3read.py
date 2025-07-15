# SPDX-FileCopyrightText: 2025-present Arthit Suriyawongkul <suriyawa@tcd.ie>
# SPDX-FileType: SOURCE
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

import argparse
from datetime import datetime
import json

from dataclasses import dataclass, field
from typing import Dict, List, Optional, Union

from spdx_python_model import v3_0_1 as spdx3
from spdx_python_model import VERSION, bindings


@dataclass
class ComplianceElementBase:
    fields: Dict[str, str] = field(default_factory=Dict, init=False, repr=False)

    def __str__(self):
        lines: List[str] = []
        for key in self.fields:
            value = getattr(self, key)
            lines.append(f"{self.fields[key]}: {value}")
        return "\n".join(lines)

    def is_compliant(self) -> bool:
        """
        Check if the element is compliant.
        This should be overridden in subclasses to implement specific compliance checks.
        """
        return True


@dataclass
class NTIAMinimumElement(ComplianceElementBase):
    author_name: Optional[str] = None
    supplier_name: Optional[str] = None
    component_name: Optional[str] = None
    version_string: Optional[str] = None
    component_hash: Optional[str] = None
    unique_identifier: Optional[str] = None
    relationship: Optional[str] = None
    timestamp: Optional[datetime] = None

    fields: Dict[str, str] = field(
        default_factory=lambda: {
            "author_name": "Author Name",
            "supplier_name": "Supplier Name",
            "component_name": "Component Name",
            "version_string": "Version String",
            "component_hash": "Component Hash",
            "unique_identifier": "Unique Identifier",
            "relationship": "Relationship",
            "timestamp": "Timestamp",
        },
        init=False,
        repr=False,
    )

    def is_compliant(self) -> bool:
        for key in self.fields:
            value = getattr(self, key)
            if value is None or (isinstance(value, str) and value.strip() == ""):
                return False
        return True


@dataclass
class FSCTBaselineAttribute(ComplianceElementBase):
    pass


def read_json_file(filepath: str):
    with open(filepath, "r", encoding="utf-8") as f:
        return json.load(f)


def deserialize_spdx_json_file(filepath: str) -> spdx3.SHACLObjectSet:
    object_set = spdx3.SHACLObjectSet()
    with open(filepath, "r", encoding="utf-8") as f:
        spdx3.JSONLDDeserializer().read(f, object_set)
        return object_set


def get_names(
    items: Union[spdx3.Element, List[spdx3.Element]], delimiter: str = "; "
) -> Optional[str]:
    if isinstance(items, spdx3.Element):
        return getattr(items, "name")

    str_list: List[str] = []
    for item in items:
        name = getattr(item, "name")
        if name is None:
            pass
        str_list.append(name)

    return delimiter.join(str_list)


def get_hash_values(
    items: Union[spdx3.Hash, List[spdx3.Hash]], delimiter: str = "; "
) -> Optional[str]:
    if isinstance(items, spdx3.Hash):
        return getattr(items, "hashValue")

    str_list: List[str] = []
    for item in items:
        algorithm = getattr(item, "algorithm")
        hash_value = getattr(item, "hashValue")
        if (
            not algorithm
            or algorithm.strip() == ""
            or not hash_value
            or hash_value.strip() == ""
        ):
            pass
        algorithm = algorithm.split("/")[-1]  # Get the last part of the IRI
        str_list.append(f"{algorithm}:{hash_value}")

    return delimiter.join(str_list)


def get_ntia_minimum_element(
    spdx_object_set: spdx3.SHACLObjectSet,
) -> NTIAMinimumElement:
    ntia = NTIAMinimumElement()

    spdx_documents: List[spdx3.SHACLObject] = list(
        spdx_object_set.foreach_type(spdx3.SpdxDocument)
    )
    if len(spdx_documents) != 1:
        raise ValueError(
            "There should be exactly one SpdxDocument object in an SPDX 3 JSON file."
        )

    doc: spdx3.SpdxDocument = spdx_documents[0]
    creation_info = getattr(doc, "creationInfo")
    if creation_info:
        created_by = getattr(creation_info, "createdBy")
        if created_by:
            ntia.author_name = get_names(created_by)
        ntia.timestamp = getattr(creation_info, "created")
        ntia.version_string = getattr(creation_info, "specVersion")

    root_element = getattr(doc, "rootElement")
    if not root_element or len(root_element) != 1:
        raise ValueError(
            "There should be exactly one root element in the SPDX document."
        )
    root_element = root_element[0]  # get the first element

    # If the root element is Bom or software_Bom, go further to get the actual root element
    if isinstance(root_element, (spdx3.Bom, spdx3.software_Sbom)):
        root_element = getattr(root_element, "rootElement")
        if not root_element or len(root_element) != 1:
            raise ValueError("There should be exactly one root element in the BOM.")
        root_element = root_element[0]

    ntia.component_name = getattr(root_element, "name")
    ntia.unique_identifier = getattr(root_element, "spdxId")

    supplied_by = getattr(root_element, "suppliedBy")
    if supplied_by:
        ntia.supplier_name = get_names(supplied_by)

    integrity_method = getattr(root_element, "verifiedUsing")
    if integrity_method:
        ntia.component_hash = get_hash_values(integrity_method)

    return ntia


def print_relationships(relationships: List[spdx3.Relationship]):
    for rel in relationships:
        from_ = getattr(rel[1], "from_")
        to = getattr(rel[1], "to")
        rel_type = getattr(rel[1], "relationshipType")
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
        relationships = spdx_object_set.obj_by_type["Relationship"]
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
        exit(1)

    print("Compliant with NTIA Minimum Element requirements.")


if __name__ == "__main__":
    main()
