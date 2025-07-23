# SPDX-FileCopyrightText: 2025-present Arthit Suriyawongkul <suriyawa@tcd.ie>
# SPDX-FileType: SOURCE
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

import argparse
import json
import sys

from abc import ABC, abstractmethod
from dataclasses import dataclass
from datetime import datetime
from typing import ClassVar, Dict, List, Optional, Set, Tuple, Union, cast

from spdx_python_model import VERSION, bindings
from spdx_python_model import v3_0_1 as spdx3


@dataclass
class ComplianceInfoBase(ABC):
    sbom_author_name: Optional[List[str]] = None
    sbom_timestamp: Optional[datetime] = None
    sbom_type: Optional[List[str]] = None
    sbom_primary_component: bool = False

    primary_component_name: Optional[str] = None
    primary_component_version: Optional[str] = None
    primary_component_supplier_name: Optional[List[str]] = None
    primary_component_hash: Optional[List[Tuple[str, str]]] = None
    primary_component_unique_id: Optional[List[Tuple[str, str]]] = None
    primary_component_relationships: Optional[List[spdx3.Relationship]] = None
    primary_component_license: Optional[List[str]] = None
    primary_component_copyright_holder: Optional[str] = None

    component_name: bool = False
    component_version: bool = False
    component_supplier_name: bool = False
    component_hash: bool = False
    component_unique_ids: bool = False
    component_relationships: bool = False
    component_license: bool = False
    component_copyright_holder: bool = False

    labels: ClassVar[Dict[str, str]] = {
        "sbom_author_name": "SBOM Author Name",
        "sbom_timestamp": "SBOM Timestamp",
        "sbom_type": "SBOM Type",
        "sbom_primary_component": "SBOM Primary Component",
        "primary_component_name": "Primary Component Name",
        "primary_component_version": "Primary Component Version String",
        "primary_component_supplier_name": "Primary Component Supplier Name",
        "primary_component_hash": "Primary Component Cryptographic Hash",
        "primary_component_unique_id": "Primary Component Unique Identifiers",
        "primary_component_relationships": "Primary Component Relationships",
        "primary_component_license": "Primary Component License",
        "primary_component_copyright_holder": "Primary Component Copyright Holder",
        "component_name": "All components have Name",
        "component_version": "All components have Version String",
        "component_supplier_name": "All components have Supplier Name",
        "component_hash": "All components have Cryptographic Hash",
        "component_unique_ids": "All components have Unique Identifiers",
        "component_relationships": "All components have Relationships",
        "component_license": "All components have License",
        "component_copyright_holder": "All components have Copyright Holder",
    }

    def __str__(self):
        lines: List[str] = [self.__class__.__name__ + ":"]
        for key, label in self.labels.items():
            value = getattr(self, key, None)
            lines.append(f"{label}: {value}")
        return "\n- ".join(lines)

    @property
    @abstractmethod
    def compliance_standard(sef) -> str:
        """
        Return the name of the compliance standard this class is checking against.
        This should be overridden in subclasses to specify the compliance standard.
        """
        raise NotImplementedError("Subclasses must implement compliance_standard.")

    @abstractmethod
    def is_compliant(self) -> bool:
        """
        Check if the element is compliant.
        This should be overridden in subclasses to implement specific compliance checks.
        """
        raise NotImplementedError("Subclasses must implement is_compliant.")


@dataclass
class NTIAMinimumElement(ComplianceInfoBase):
    labels: ClassVar[Dict[str, str]] = {
        **ComplianceInfoBase.labels,
        "sbom_type": "Lifecycle Phase",
    }

    @property
    def compliance_standard(self) -> str:
        return "NTIA Minimum Element"

    def is_compliant(self) -> bool:
        for key in self.labels:
            value = getattr(self, key, None)
            if value is None or (isinstance(value, str) and value.strip() == ""):
                return False
        return True


@dataclass
class FSCTBaselineAttribute(ComplianceInfoBase):
    @property
    def compliance_standard(self) -> str:
        return "FSCT Baseline Attribute"

    def is_compliant(self) -> bool:
        for key in self.labels:
            value = getattr(self, key, None)
            if value is None or (isinstance(value, str) and value.strip() == ""):
                return False
        return True


def read_json_file(filepath: str):
    with open(filepath, encoding="utf-8") as f:
        return json.load(f)


def deserialize_spdx_json_file(filepath: str) -> spdx3.SHACLObjectSet:
    object_set = spdx3.SHACLObjectSet()
    with open(filepath, encoding="utf-8") as f:
        spdx3.JSONLDDeserializer().read(f, object_set)
        return object_set


def get_names(
    items: Union[spdx3.Element, List[spdx3.Element]], delimiter: str = "; "
) -> Optional[str]:
    if isinstance(items, spdx3.Element):
        return getattr(items, "name")

    items = cast(List[spdx3.Element], items)
    str_list: List[str] = []
    for item in items:
        name = getattr(item, "name")
        if name is None:
            continue
        str_list.append(name)

    return delimiter.join(str_list)


def get_hash_values(
    items: Union[spdx3.Hash, List[spdx3.Hash]], delimiter: str = "; "
) -> Optional[str]:
    if isinstance(items, spdx3.Hash):
        return getattr(items, "hashValue")

    items = cast(List[spdx3.Hash], items)
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
            continue
        algorithm = algorithm.split("/")[-1]  # Get the last part of the IRI
        str_list.append(f"{algorithm}:{hash_value}")

    return delimiter.join(str_list)


def get_compliance_info(
    spdx_object_set: spdx3.SHACLObjectSet, info_base: ComplianceInfoBase
) -> None:
    spdx_documents: List[spdx3.SpdxDocument] = list(
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
            names: List[str] = []
            for agent in created_by:
                name = getattr(agent, "name")
                if name:
                    names.append(name)
            info_base.sbom_author_name = names
        info_base.sbom_timestamp = getattr(creation_info, "created")

    root_element = getattr(doc, "rootElement")
    if not root_element or len(root_element) != 1:
        raise ValueError(
            "There should be exactly one root element in the SPDX document."
        )
    root_element = root_element[0]  # get the first element

    # If the root element is Bom or software_Bom, go further to get the actual root element
    if isinstance(root_element, (spdx3.Bom, spdx3.software_Sbom)):
        if isinstance(root_element, spdx3.software_Sbom) and hasattr(
            root_element, "software_sbomType"
        ):
            sbom_types = getattr(root_element, "software_sbomType")  # return a list
            temp: List[str] = []
            for sbom_type in sbom_types:
                temp.append(sbom_type.split("/")[-1])
            if temp:
                info_base.sbom_type = temp
        root_element = getattr(root_element, "rootElement")
        if not root_element or len(root_element) != 1:
            raise ValueError("There should be exactly one root element in the BOM.")
        root_element = root_element[0]
        # root_element_id = getattr(root_element, "spdxId")
        if not isinstance(root_element, spdx3.software_Package):
            raise ValueError("The root element should be a Software/Package.")

    if root_element:
        info_base.sbom_primary_component = True

    info_base.primary_component_name = getattr(root_element, "name")
    info_base.primary_component_version = getattr(
        root_element, "software_packageVersion"
    )

    ids: Set[Tuple[str, str]] = set()
    id_types = ["spdxId", "software_contentIdentifier", "externalIdentifier"]
    for id_type in id_types:
        if getattr(root_element, id_type):
            ids.add((id_type, getattr(root_element, id_type)))

    info_base.primary_component_unique_id = list(ids)

    supplied_by = getattr(root_element, "suppliedBy")
    if supplied_by:
        info_base.primary_component_supplier_name = getattr(supplied_by, "name")

    integrity_method = getattr(root_element, "verifiedUsing")
    if integrity_method:
        hashes: List[Tuple[str, str]] = []
        for method in integrity_method:
            algorithm = getattr(method, "algorithm")
            hash_value = getattr(method, "hashValue")
            if (
                not algorithm
                or algorithm.strip() == ""
                or not hash_value
                or hash_value.strip() == ""
            ):
                pass
            algorithm = algorithm.split("/")[-1]  # Get the last part of the IRI
            hashes.append((algorithm, hash_value))

        info_base.primary_component_hash = hashes

    component_licenses: Set[str] = set()

    for rel in spdx_object_set.foreach_type(spdx3.Relationship):  # type: ignore
        rel = cast(spdx3.Relationship, rel)
        from_ = getattr(rel, "from_")
        if from_ == root_element and hasattr(rel, "relationshipType"):
            rel_type = getattr(rel, "relationshipType").split("/")[-1]
            if rel_type in [
                "hasConcludedLicense",
                "hasDeclaredLicense",
            ]:
                tos = getattr(rel, "to")  # return a list
                for to in tos:
                    if isinstance(to, spdx3.simplelicensing_AnyLicenseInfo):
                        license = "Unknown license object"
                        if isinstance(to, spdx3.simplelicensing_LicenseExpression):
                            license = getattr(to, "simplelicensing_licenseExpression")
                        elif isinstance(to, spdx3.simplelicensing_SimpleLicensingText):
                            license = getattr(to, "simplelicensing_licenseText")
                        # component_licenses.append(license)
                        component_licenses.add(license)

    if component_licenses:
        info_base.primary_component_license = list(component_licenses)

    if isinstance(root_element, spdx3.software_SoftwareArtifact) and getattr(
        root_element, "software_copyrightText"
    ):
        info_base.primary_component_copyright_holder = getattr(
            root_element, "software_copyrightText"
        )

    # Check all components for mandatory fields
    all_have_id = True
    all_have_name = True
    all_have_supplier = True
    all_have_version = True
    for obj in spdx_object_set.foreach_type(spdx3.software_SoftwareArtifact):  # type: ignore
        obj = cast(spdx3.software_SoftwareArtifact, obj)
        id = getattr(obj, "spdxId")
        all_have_id = all_have_id and (id is not None and id.strip() != "")

        name = getattr(obj, "name")
        all_have_name = all_have_name and (name is not None and name.strip() != "")

        supplier = getattr(obj, "suppliedBy")
        all_have_supplier = (
            all_have_supplier
            and (supplier is not None)
            and hasattr(supplier, "name")
            and getattr(supplier, "name").strip() != ""
        )

        if isinstance(obj, spdx3.software_Package):
            version = getattr(obj, "software_packageVersion")
            all_have_version = all_have_version and (
                version is not None and version.strip() != ""
            )

    info_base.component_unique_ids = all_have_id
    info_base.component_name = all_have_name
    info_base.component_supplier_name = all_have_supplier
    info_base.component_version = all_have_version


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
    get_compliance_info(spdx_object_set, info_base)

    if args.print:
        print(info_base)

    if not info_base.is_compliant():
        print(f"Not compliant with {info_base.compliance_standard} requirements.")
        sys.exit(1)

    print(f"Compliant with {info_base.compliance_standard} requirements.")


if __name__ == "__main__":
    main()


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
