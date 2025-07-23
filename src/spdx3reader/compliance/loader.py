# SPDX-FileCopyrightText: 2025-present Arthit Suriyawongkul <suriyawa@tcd.ie>
# SPDX-FileType: SOURCE
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

from typing import List, Optional, Set, Tuple, Union, cast

from spdx_python_model import v3_0_1 as spdx3

from .models import ComplianceInfo


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


def load_compliance_info(
    spdx_object_set: spdx3.SHACLObjectSet, info_base: ComplianceInfo
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
