# SPDX-FileCopyrightText: 2025-present Arthit Suriyawongkul <suriyawa@tcd.ie>
# SPDX-FileType: SOURCE
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass
from datetime import datetime
from typing import ClassVar, Dict, List, Optional, Tuple

from spdx_python_model import v3_0_1 as spdx3


@dataclass
class ComplianceInfo(ABC):
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
    def compliance_standard(self) -> str:
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
class NTIAMinimumElement(ComplianceInfo):
    labels: ClassVar[Dict[str, str]] = {
        **ComplianceInfo.labels,
        "sbom_type": "Lifecycle Phase",  # NTIA Minimum Element uses this label for SBOM Type
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
class FSCTBaselineAttribute(ComplianceInfo):
    @property
    def compliance_standard(self) -> str:
        return "FSCT Baseline Attribute"

    def is_compliant(self) -> bool:
        for key in self.labels:
            value = getattr(self, key, None)
            if value is None or (isinstance(value, str) and value.strip() == ""):
                return False
        return True
