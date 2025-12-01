#!/bin/python3

# © 2025 Nokia
# Author: Marc-Etienne Vargenau
# Licensed under the Apache License 2.0
# SPDX-License-Identifier: Apache-2.0

"""Module creating an SPDX SBOM for a pypi.org package."""

import sys
import os
import platform
import datetime
import re
import json
import urllib.request
import tarfile
import subprocess
import argparse
import traceback # Import traceback for detailed error logging
import requests
import spdx_license_list
from spdx_tools.spdx.parser.parse_anything import parse_file
from spdx_tools.spdx.writer.write_anything import write_file

# --- Constants for improved readability and maintainability ---
SPDX_VERSION = "SPDX-2.3"
DATA_LICENSE = "CC0-1.0"
SPDX_DOCUMENT_REF = "SPDXRef-DOCUMENT"
CREATOR_TOOL = "pypispdx - 0.1.0"
LICENSE_LIST_VERSION = "3.27"
CISA_SBOM_TYPE = "Analyzed"
PACKAGE_SUPPLIER = "Organization: https://pypi.org"
FILES_ANALYZED = "false"
PACKAGE_COPYRIGHT_TEXT = "NOASSERTION"
PURL_EXTERNAL_REF_TYPE = "PACKAGE-MANAGER purl pkg:pypi/"

# Mapping for common OSI-approved licenses from classifiers
CLASSIFIER_LICENSE_MAP = {
    "License :: Aladdin Free Public License (AFPL)": "Aladdin",
    "License :: Nokia Open Source License (NOKOS)": "Nokia",
    "License :: OSI Approved :: Apache Software License": "Apache-2.0",
    "License :: OSI Approved :: Attribution Assurance License": "AAL",
    "License :: OSI Approved :: Boost Software License 1.0 (BSL-1.0)": "BSL-1.0",
    "License :: OSI Approved :: CEA CNRS Inria Logiciel Libre License, version 2.1 (CeCILL-2.1)": "CECILL-2.1",
    "License :: OSI Approved :: Common Public License": "CPL-1.0",
    "License :: OSI Approved :: European Union Public Licence 1.0 (EUPL 1.0)": "EUPL-1.0",
    "License :: OSI Approved :: European Union Public Licence 1.1 (EUPL 1.1)": "EUPL-1.1",
    "License :: OSI Approved :: GNU Affero General Public License v3": "AGPL-3.0-only",
    "License :: OSI Approved :: GNU Affero General Public License v3 or later (AGPLv3+)": "AGPL-3.0-or-later",
    "License :: OSI Approved :: GNU General Public License v2 (GPLv2)": "GPL-2.0-only",
    "License :: OSI Approved :: GNU General Public License v2 or later (GPLv2+)": "GPL-2.0-or-later",
    "License :: OSI Approved :: GNU General Public License v3 (GPLv3)": "GPL-3.0-only",
    "License :: OSI Approved :: GNU General Public License v3 or later (GPLv3+)": "GPL-3.0-or-later",
    "License :: OSI Approved :: GNU Lesser General Public License v2 or later (LGPLv2+)": "LGPL-2.0-or-later",
    "License :: OSI Approved :: GNU Lesser General Public License v3 (LGPLv3)": "LGPL-3.0-only",
    "License :: OSI Approved :: GNU Lesser General Public License v3 or later (LGPLv3+)": "LGPL-3.0-or-later",
    "License :: OSI Approved :: IBM Public License": "IPL-1.0",
    "License :: OSI Approved :: Intel Open Source License": "Intel",
    "License :: OSI Approved :: ISC License (ISCL)": "ISC",
    "License :: OSI Approved :: MIT License": "MIT",
    "License :: OSI Approved :: Motosoto License": "Motosoto",
    "License :: OSI Approved :: Mozilla Public License 1.0 (MPL)": "MPL-1.0",
    "License :: OSI Approved :: Mozilla Public License 1.1 (MPL 1.1)": "MPL-1.1",
    "License :: OSI Approved :: Mozilla Public License 2.0 (MPL 2.0)": "MPL-2.0",
    "License :: OSI Approved :: Nethack General Public License": "NGPL",
    "License :: OSI Approved :: Nokia Open Source License": "Nokia",
    "License :: OSI Approved :: Open Group Test Suite License": "OGTSL",
    "License :: OSI Approved :: Python License (CNRI Python License)": "CNRI-Python",
    "License :: OSI Approved :: Python Software Foundation License": "PSF-2.0",
    "License :: OSI Approved :: Ricoh Source Code Public License": "RSCPL",
    "License :: OSI Approved :: Sleepycat License": "Sleepycat",
    "License :: OSI Approved :: Sun Public License": "SPL-1.0",
    "License :: OSI Approved :: The Unlicense (Unlicense)": "Unlicense",
    "License :: OSI Approved :: University of Illinois/NCSA Open Source License": "NCSA",
    "License :: OSI Approved :: Vovida Software License 1.0": "VSL-1.0",
    "License :: OSI Approved :: W3C License": "W3C-20150513",
    "License :: OSI Approved :: X.Net License": "Xnet",
}

# Deprecated license identifiers mapping
DEPRECATED_LICENSES_MAP = {
    "GPL-2.0": "GPL-2.0-only",
    "GPL-2.0+": "GPL-2.0-or-later",
    "LGPL-2.0": "LGPL-2.0-only",
    "LGPL-2.0+": "LGPL-2.0-or-later",
    "LGPL-2.1": "LGPL-2.1-only",
    "LGPL-2.1+": "LGPL-2.1-or-later",
}

class PyPISPDXError(Exception):
    """Custom exception for PyPI SPDX generation errors."""
    pass

def dash_name(input_string: str) -> str:
    """
    Replaces underscore and dot characters in a string with dashes,
    and converts uppercase letters to lowercase.

    Parameter:
    - input_string (str): The string to process.

    Returns:
    - str: The processed string.
    """
    return input_string.strip().replace("_", "-").replace(".", "-").lower()

def get_package_info(package_name: str, debug_mode: bool) -> dict | None:
    """
    Fetches information about a package from PyPI.

    Parameter:
    - package_name (str): The name of the package to fetch information about.
    - debug_mode (bool): If True, print debug information.

    Returns:
    - dict: A dictionary containing the package information, or None if not found or an error occurs.
    """
    dashed_package_name = dash_name(package_name)
    url = f"https://pypi.org/pypi/{dashed_package_name}/json"
    if debug_mode:
        print(f"DEBUG: Fetching package info from: {url}", file=sys.stderr)
    try:
        response = requests.get(url, timeout=10) # Added timeout for robustness
        if debug_mode:
            print(f"DEBUG: Response status for {package_name}: {response.status_code}", file=sys.stderr)
        response.raise_for_status() # Raises HTTPError for bad responses (4xx or 5xx)
        return response.json()
    except requests.exceptions.RequestException as e:
        print(f"Error fetching package info for {package_name}: {e}", file=sys.stderr)
        if debug_mode:
            traceback.print_exc(file=sys.stderr)
        return None

def print_spdx_header(package_name: str, package_version: str, sbom_file_object) -> None:
    """
    Prints the SPDX header to the SBOM file.

    Parameters:
    - package_name (str): The name of the main package.
    - package_version (str): The version of the main package.
    - sbom_file_object (io.TextIOWrapper): The SBOM file object where to write.
    """
    dashed_package_name = dash_name(package_name)

    sbom_file_object.write(f"SPDXVersion: {SPDX_VERSION}\n")
    sbom_file_object.write(f"DataLicense: {DATA_LICENSE}\n")
    sbom_file_object.write(f"SPDXID: {SPDX_DOCUMENT_REF}\n")
    sbom_file_object.write(f"DocumentName: {dashed_package_name}-{package_version}\n")

    sbom_file_object.write(f"DocumentNamespace: https://pypi.org/spdx/{dashed_package_name}-{package_version}\n\n")

    sbom_file_object.write("## Creation Information\n\n")
    sbom_file_object.write(f"LicenseListVersion: {LICENSE_LIST_VERSION}\n")

    organization = os.getenv("ORGANIZATION", "UNKNOWN")
    sbom_file_object.write(f"Creator: Organization: {organization}\n")
    sbom_file_object.write(f"Creator: Tool: {CREATOR_TOOL}\n")

    # Use datetime.UTC if available (Python 3.11+), otherwise use datetime.timezone.utc
    utc_tz = getattr(datetime, 'UTC', datetime.timezone.utc)
    sbom_file_object.write(f"Created: {datetime.datetime.now(utc_tz).strftime('%Y-%m-%dT%H:%M:%SZ')}\n")
    sbom_file_object.write("CreatorComment: <text>")
    sbom_file_object.write(f"CISA SBOM type: {CISA_SBOM_TYPE}\n")
    sbom_file_object.write(f"This SBOM was created with Python version {platform.python_version()}")
    sbom_file_object.write("</text>\n\n")

def _get_spdx_license_from_classifiers(classifiers: list, unknown_licenses_list: list, debug_mode: bool) -> str | None:
    """
    Determines the SPDX license identifier(s) from PyPI classifiers.

    Parameters:
    - classifiers (list): List of classifier strings from PyPI.
    - unknown_licenses_list (list): A list to append details of unknown licenses.
    - debug_mode (bool): If True, print debug information.

    Returns:
    - str | None: The SPDX license expression, or None if no license could be determined.
    """
    licenses = set()
    for classifier in classifiers:
        if classifier in CLASSIFIER_LICENSE_MAP:
            licenses.add(CLASSIFIER_LICENSE_MAP[classifier])
            if debug_mode:
                print(f"DEBUG: Classifier '{classifier}' mapped to SPDX '{CLASSIFIER_LICENSE_MAP[classifier]}'", file=sys.stderr)
        elif classifier.startswith("License ::") and classifier != "License :: OSI Approved":
            # Generate a unique LicenseRef for unknown licenses
            licenseref_base = re.sub(r'[^a-zA-Z0-9]', '-', classifier)
            licenseref = "LicenseRef-unknown-" + re.sub('-+', '-', licenseref_base).strip('-')
            licenses.add(licenseref)
            unknown = {"id": licenseref, "text": classifier}
            if unknown not in unknown_licenses_list:
                unknown_licenses_list.append(unknown)
            if debug_mode:
                print(f"DEBUG: Classifier '{classifier}' identified as unknown, assigned LicenseRef '{licenseref}'", file=sys.stderr)

    if len(licenses) == 1:
        return list(licenses)[0]
    elif len(licenses) >= 2:
        return " AND ".join(sorted(licenses))
    return None

def print_package(package_name: str, package_version: str, sbom_file_object,
                  custom_licenses_list: list, unknown_licenses_list: list, debug_mode: bool) -> None:
    """
    Prints the SPDX package information to the SBOM file.

    Parameters:
    - package_name (str): The name of the package.
    - package_version (str): The version of the package.
    - sbom_file_object (io.TextIOWrapper): The SBOM file object where to write.
    - custom_licenses_list (list): A list to store custom license details.
    - unknown_licenses_list (list): A list to store unknown license details.
    - debug_mode (bool): If True, print debug information.
    """
    dashed_package_name = dash_name(package_name)
    if debug_mode:
        print(f"DEBUG: Processing package: {package_name} (version: {package_version})", file=sys.stderr)
    package_info = get_package_info(dashed_package_name, debug_mode)

    if not package_info:
        raise PyPISPDXError(f"Package '{package_name}' cannot be found in https://pypi.org/")

    info = package_info["info"]

    sbom_file_object.write(f"##### Package: {dashed_package_name}\n\n")
    sbom_file_object.write(f"PackageName: {dashed_package_name}\n")
    sbom_file_object.write(f"SPDXID: SPDXRef-{dashed_package_name}\n")
    sbom_file_object.write(f"PackageVersion: {package_version}\n")
    sbom_file_object.write(f"PackageSupplier: {PACKAGE_SUPPLIER}\n")

    download_location = "NOASSERTION"
    sha256 = ""
    md5 = ""

    # Find the .tar.gz distribution for the specific version
    releases = package_info.get("releases", {})
    if package_version in releases:
        if debug_mode:
            print(f"DEBUG: Looking for tar.gz for {package_name}@{package_version} in releases.", file=sys.stderr)
        for release_file in releases[package_version]:
            filename = release_file.get("filename", "").lower()
            if filename.endswith(".tar.gz"):
                # Ensure we pick the correct tar.gz for the package name
                # e.g., 'mypackage-1.0.tar.gz' for 'mypackage'
                filename = filename.removesuffix("-" + package_version + ".tar.gz")
                filename = filename.replace(".", "-")
                underscored_package_name = package_name.replace("-", "_").replace(".", "_").lower()
                if filename in (underscored_package_name, dashed_package_name, package_name):
                    download_location = release_file.get("url", "NOASSERTION")
                    digests = release_file.get("digests", {})
                    sha256 = digests.get("sha256", "")
                    md5 = digests.get("md5", "")
                    if debug_mode:
                        print(f"DEBUG: Found tar.gz: {filename}, URL: {download_location}", file=sys.stderr)
                    break # Found the relevant tar.gz, exit loop
    else:
        if debug_mode:
            print(f"DEBUG: No releases found for {package_name}@{package_version}.", file=sys.stderr)


    sbom_file_object.write(f"PackageDownloadLocation: {download_location}\n")
    sbom_file_object.write(f"FilesAnalyzed: {FILES_ANALYZED}\n")

    if sha256:
        sbom_file_object.write(f"PackageChecksum: SHA256: {sha256}\n")
    if md5:
        sbom_file_object.write(f"PackageChecksum: MD5: {md5}\n")

    spdx_license = info.get("license_expression")
    if debug_mode:
        print(f"DEBUG: Initial license_expression for {package_name}: {spdx_license}", file=sys.stderr)

    # If no license_expression, try 'license' field
    if not spdx_license:
        license_field = info.get("license")
        if license_field:
            if debug_mode:
                print(f"DEBUG: No license_expression, checking 'license' field: {license_field}", file=sys.stderr)
            if license_field in spdx_license_list.LICENSES:
                spdx_license = DEPRECATED_LICENSES_MAP.get(license_field, license_field)
                if debug_mode:
                    print(f"DEBUG: 'license' field is valid SPDX: {spdx_license}", file=sys.stderr)
            else:
                if debug_mode:
                    print(f"DEBUG: 'license' field '{license_field}' is not a known SPDX ID.", file=sys.stderr)
                # If 'license' field is not a known SPDX ID, treat as NOASSERTION for now
                # and check classifiers next.
                pass

    # Check for custom licenses (LicenseRef- with no spaces)
    if spdx_license and spdx_license.startswith("LicenseRef-") and " " not in spdx_license:
        license_files = info.get("license_files", [])
        if len(license_files) == 1:
            custom = {"id": spdx_license, "file": license_files[0], "download_location": download_location}
            custom_licenses_list.append(custom)
            if debug_mode:
                print(f"DEBUG: Identified custom license: {spdx_license} from file {license_files[0]}", file=sys.stderr)

    # If still no license, try classifiers
    if not spdx_license or spdx_license == "NOASSERTION": # Check for explicit NOASSERTION from previous step
        if debug_mode:
            print(f"DEBUG: No license found yet, checking classifiers for {package_name}.", file=sys.stderr)
        classifiers = info.get("classifiers", [])
        classifier_spdx_license = _get_spdx_license_from_classifiers(classifiers, unknown_licenses_list, debug_mode)
        if classifier_spdx_license:
            spdx_license = classifier_spdx_license
            if debug_mode:
                print(f"DEBUG: License determined from classifiers: {spdx_license}", file=sys.stderr)
        else:
            spdx_license = "NOASSERTION" # Default if nothing found
            if debug_mode:
                print(f"DEBUG: No license could be determined for {package_name}, setting to NOASSERTION.", file=sys.stderr)

    sbom_file_object.write(f"PackageLicenseConcluded: {spdx_license}\n")
    sbom_file_object.write(f"PackageLicenseDeclared: {spdx_license}\n")
    sbom_file_object.write(f"PackageCopyrightText: {PACKAGE_COPYRIGHT_TEXT}\n")
    sbom_file_object.write(f"ExternalRef: {PURL_EXTERNAL_REF_TYPE}{dashed_package_name}@{package_version}\n\n")

def _process_custom_license_file(custom_license_entry: dict, sbom_file_object, debug_mode: bool) -> None:
    """
    Downloads, extracts, and writes the text of a custom license to the SBOM.

    Parameters:
    - custom_license_entry (dict): Dictionary containing 'id', 'file', and 'download_location'.
    - sbom_file_object (io.TextIOWrapper): The SBOM file object where to write.
    - debug_mode (bool): If True, print debug information.
    """
    license_id = custom_license_entry["id"]
    download_url = custom_license_entry["download_location"]
    license_file_in_archive = custom_license_entry["file"]

    if debug_mode:
        print(f"DEBUG: Processing custom license '{license_id}' from '{download_url}'", file=sys.stderr)

    sbom_file_object.write(f"LicenseID: {license_id}\n")
    license_name = license_id.replace('LicenseRef-', '')
    sbom_file_object.write(f"LicenseName: {license_name}\n")

    if download_url == "NOASSERTION":
        sbom_file_object.write("ExtractedText: <text>License file not available for download.</text>\n")
        if debug_mode:
            print(f"DEBUG: Custom license '{license_id}' has NOASSERTION download location.", file=sys.stderr)
        return

    tar_filename = os.path.basename(download_url)
    temp_dir = f"temp_license_extract_{os.getpid()}" # Use PID for unique temp dir

    try:
        os.makedirs(temp_dir, exist_ok=True)
        temp_tar_path = os.path.join(temp_dir, tar_filename)

        if debug_mode:
            print(f"DEBUG: Downloading custom license from {download_url} to {temp_tar_path}", file=sys.stderr)
        urllib.request.urlretrieve(download_url, temp_tar_path)

        with tarfile.open(temp_tar_path, "r:gz") as tar:
            # Extract only the specific license file to avoid extracting everything
            # Find the member that matches the license file path
            members = [m for m in tar.getmembers() if m.name.endswith(license_file_in_archive)]
            if not members:
                raise PyPISPDXError(f"License file '{license_file_in_archive}' not found in archive '{tar_filename}'")

            # Extract the first matching member
            extracted_member_name = members[0].name
            if debug_mode:
                print(f"DEBUG: Extracting '{extracted_member_name}' from '{tar_filename}'", file=sys.stderr)
            tar.extract(members[0], path=temp_dir)
            extracted_file_path = os.path.join(temp_dir, extracted_member_name)

            with open(extracted_file_path, "rb") as lic_f:
                lic_text = lic_f.read().decode("utf-8", errors='replace') # Use 'replace' for encoding errors

            sbom_file_object.write("ExtractedText: <text>")
            sbom_file_object.write(lic_text)
            sbom_file_object.write("</text>\n")

    except (urllib.error.URLError, tarfile.ReadError, IOError, PyPISPDXError) as e:
        print(f"Warning: Could not process custom license '{license_id}' from '{download_url}': {e}", file=sys.stderr)
        if debug_mode:
            traceback.print_exc(file=sys.stderr)
        sbom_file_object.write(f"ExtractedText: <text>Error retrieving or extracting license text: {e}</text>\n")
    finally:
        # Clean up temporary files and directory
        if os.path.exists(temp_dir):
            if debug_mode:
                print(f"DEBUG: Cleaning up temporary directory: {temp_dir}", file=sys.stderr)
            for root, dirs, files in os.walk(temp_dir, topdown=False):
                for name in files:
                    os.remove(os.path.join(root, name))
                for name in dirs:
                    os.rmdir(os.path.join(root, name))
            os.rmdir(temp_dir)

def main():
    """
    Main function to generate an SPDX SBOM for a PyPI package and its dependencies.
    """
    parser = argparse.ArgumentParser(
        description="Create an SPDX SBOM for a pypi.org package and its dependencies."
    )
    parser.add_argument(
        "package_name",
        help="The name of the PyPI package to create an SBOM for."
    )
    parser.add_argument(
        "--debug",
        action="store_true",
        help="Enable debug output, including detailed messages and full tracebacks."
    )
    spdxformat = parser.add_mutually_exclusive_group()
    spdxformat.add_argument(
        "--json",
        action="store_true",
        help="Output the result in SPDX JSON format."
    )
    spdxformat.add_argument(
        "--rdf",
        action="store_true",
        help="Output the result in SPDX RDF format."
    )
    spdxformat.add_argument(
        "--xml",
        action="store_true",
        help="Output the result in SPDX XML format."
    )
    spdxformat.add_argument(
        "--yaml",
        action="store_true",
        help="Output the result in SPDX YAML format."
    )
    args = parser.parse_args()

    main_package_name = args.package_name
    debug_mode = args.debug

    if debug_mode:
        print("DEBUG: Debug mode is enabled.", file=sys.stderr)
    print(f"Creating SPDX SBOM for PyPI package {main_package_name}")

    sbom_filename = "" # Initialize for cleanup in case of early error
    try:
        main_package_info = get_package_info(main_package_name, debug_mode)
        if not main_package_info:
            raise PyPISPDXError(f"Main package '{main_package_name}' cannot be found in https://pypi.org/")

        main_info = main_package_info["info"]
        main_version = main_info["version"]
        main_package_dashed = dash_name(main_package_name)

        sbom_filename = f"{main_package_dashed}-{main_version}.spdx"
        custom_licenses = []
        unknown_licenses = []

        with open(sbom_filename, "w", encoding="utf-8") as sbom:
            print_spdx_header(main_package_name, main_version, sbom)
            print_package(main_package_name, main_version, sbom, custom_licenses, unknown_licenses, debug_mode)

            # Use subprocess.run for better control over external commands
            temp_json_report = f"{main_package_dashed}_pip_report.json"
            pip_command = [
                sys.executable, "-m", "pip", "install",
                "--dry-run", "--ignore-installed",
                main_package_name,
                "--report", temp_json_report
            ]
            if debug_mode:
                print(f"DEBUG: Running pip command to get dependencies: {' '.join(pip_command)}", file=sys.stderr)
            try:
                result = subprocess.run(pip_command, check=True, capture_output=True, text=True)
                if debug_mode:
                    print(f"DEBUG: pip stdout:\n{result.stdout}", file=sys.stderr)
                    print(f"DEBUG: pip stderr:\n{result.stderr}", file=sys.stderr)
            except subprocess.CalledProcessError as e:
                print(f"Error running pip: {e.stderr}", file=sys.stderr)
                if debug_mode:
                    traceback.print_exc(file=sys.stderr)
                raise PyPISPDXError(f"Failed to get dependencies for {main_package_name}.")

            if not os.path.isfile(temp_json_report):
                raise PyPISPDXError(f"Pip report file '{temp_json_report}' was not created.")

            with open(temp_json_report, encoding="utf-8") as json_data_file:
                pip_report_data = json.load(json_data_file)
            os.remove(temp_json_report)
            if debug_mode:
                print(f"DEBUG: Pip report file '{temp_json_report}' processed and removed.", file=sys.stderr)

            dependencies = []
            for dependency_entry in pip_report_data.get("install", []):
                metadata = dependency_entry.get("metadata", {})
                name = metadata.get("name")
                version = metadata.get("version")
                if name and version:
                    dependencies.append({"name": name, "version": version})
            if debug_mode:
                print(f"DEBUG: Found {len(dependencies)} dependencies.", file=sys.stderr)

            # Sort dependencies for consistent SBOM output
            dependencies = sorted(dependencies, key=lambda x: dash_name(x['name']))

            for dep in dependencies:
                dep_name_dashed = dash_name(dep["name"])
                if dep_name_dashed != main_package_dashed: # Avoid re-printing the main package
                    print_package(dep["name"], dep["version"], sbom, custom_licenses, unknown_licenses, debug_mode)

            sbom.write("##### Relationships\n\n")
            sbom.write(f"Relationship: {SPDX_DOCUMENT_REF} DESCRIBES SPDXRef-{main_package_dashed}\n")

            for dep in dependencies:
                dep_name_dashed = dash_name(dep["name"])
                if dep_name_dashed != main_package_dashed:
                    sbom.write(f"Relationship: SPDXRef-{main_package_dashed} CONTAINS SPDXRef-{dep_name_dashed}\n")

            # Print custom and unknown licenses if any were found
            if custom_licenses or unknown_licenses:
                sbom.write("\n##### Custom licenses\n\n")

            for cust_license in custom_licenses:
                _process_custom_license_file(cust_license, sbom, debug_mode)

            for unk_license in unknown_licenses:
                if debug_mode:
                    print(f"DEBUG: Adding unknown license: {unk_license['id']}", file=sys.stderr)
                sbom.write(f"LicenseID: {unk_license['id']}\n")
                license_name = unk_license['id'].replace('LicenseRef-', '')
                sbom.write(f"LicenseName: {license_name}\n")
                sbom.write(f"ExtractedText: <text>{unk_license['text']}</text>\n")

        # Convert to JSON, RDF, XML or YAML format if needed
        if args.json:
            new_sbom_filename = sbom_filename + ".json"
        elif args.rdf:
            new_sbom_filename = sbom_filename + ".rdf"
        elif args.xml:
            new_sbom_filename = sbom_filename + ".xml"
        elif args.yaml:
            new_sbom_filename = sbom_filename + ".yaml"
        else:
            print(f"SBOM successfully created: {sbom_filename}")
            sys.exit(0)

        document = parse_file(sbom_filename)
        write_file(document, new_sbom_filename)
        os.remove(sbom_filename)
        print(f"SBOM successfully created: {new_sbom_filename}")
        sys.exit(0)

    except PyPISPDXError as e:
        print(f"Error: {e}", file=sys.stderr)
        if debug_mode:
            traceback.print_exc(file=sys.stderr) # Print full traceback in debug mode
        # Clean up partially created SBOM file if an error occurred
        if os.path.exists(sbom_filename):
            os.remove(sbom_filename)
        sys.exit(1)
    except Exception as e:
        print(f"An unexpected error occurred: {e}", file=sys.stderr)
        if debug_mode:
            traceback.print_exc(file=sys.stderr) # Print full traceback in debug mode
        if os.path.exists(sbom_filename):
            os.remove(sbom_filename)
        sys.exit(1)

if __name__ == "__main__":
    main()
