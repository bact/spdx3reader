# SPDX-FileCopyrightText: 2025-present Arthit Suriyawongkul <suriyawa@tcd.ie>
# SPDX-FileType: SOURCE
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime
from typing import Dict, List, Optional, Union

from spdx_python_model import v3_0_1 as spdx3


@dataclass
class ComplianceInfoBase(ABC):
    fields: Dict[str, str] = field(default_factory=Dict, init=False, repr=False)

    def __str__(self):
        lines: List[str] = []
        for key in self.fields:
            value = getattr(self, key)
            lines.append(f"{self.fields[key]}: {value}")
        return "\n".join(lines)

    @abstractmethod
    def is_compliant(self) -> bool:
        """
        Check if the element is compliant.
        This should be overridden in subclasses to implement specific compliance checks.
        """


@dataclass
class NTIAMinimumElement(ComplianceInfoBase):
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
class FSCTBaselineAttribute(ComplianceInfoBase):
    pass


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
