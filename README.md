# pypispdx

An SCA tool for creating an SPDX SBOM for a https://pypi.org/ package.

# Usage

```
usage: pypispdx [-h] [--json | --rdf | --xml | --yaml] [--debug] package
```

where “package” is a Python package available on https://pypi.org/

```
options:
  -h, --help            Shows this help message and exits.
  --debug               Enables debug output, including detailed messages and full tracebacks.
  --json                Output the result in SPDX JSON format.
  --rdf                 Output the result in SPDX RDF format.
  --xml                 Output the result in SPDX XML format.
  --yaml                Output the result in SPDX YAML format.
```

It will create an SPDX 2.3 SBOM for the latest available release of the package,
including all transitive dependencies.

By default, the output will be in tag:value format. The other formats, JSON, RDF,
XML and YAML are available by using the corresponding command-line option.

The SBOM filename will be ```package-version.spdx``` (plus the corresponding
suffix for the other formats), where the package name will be in lower case,
with underscores and dots replaced by dash.

Running again the command will give a different result if a newer version of the package or its
transitive dependencies are available.

Running the command with different versions of Python might give different results
as different versions of transitive dependencies might be selected.

## Content of the SBOM

The Creator Organization will be taken from the ORGANIZATION environment variable.
If not set, it will be “UNKNOWN”.

The DocumentNamespace will be ```https://pypi.org/spdx/```package-version

For each package, the ```PackageSupplier``` will be “Organization: https://pypi.org”.

The ```PackageDownloadLocation``` will be a “.tar.gz” file if available.
If not available, it will be NOASSERTION.

If available, the ```PackageChecksum``` will be provided in both SHA256 and MD5.

The ```PackageLicenseConcluded``` and ```PackageLicenseDeclared``` will be given if available on PyPI.
If not, it will be NOASSERTION. See more details below.

The ```PackageCopyrightText``` will always be NOASSERTION.

The [PURL](https://github.com/package-url/purl-spec/) (Package URL) will be provided
in the ```ExternalRef``` field.

## Licenses

First, the licenses will be searched in “license_expression” as specified in
[PEP 639](https://peps.python.org/pep-0639/).

If not available, the licenses will be searched in “license”

If no “license_expression” and no “license” they will be searched in “classifiers”

If the classifier is ambiguous, for example:
```
License :: OSI Approved :: GNU General Public License (GPL)
```
a ```LicenseRef-``` is created with that text.

When the license is specified with a ```LicenseRef-```, the text of the license
is retreived from the license file and put in the SBOM.

See for example [infinity-grid](https://pypi.org/project/infinity-grid/).

## About PURL specification

The name is case insensitive and lowercased.

Underscore “_” is replaced with dash “-”.

Dot “.” is replaced with dash “-”.

## Compliance

The SBOM is valid SPDX 2.3.

It is compliant with the [OpenChain Telco SBOM Guide](https://github.com/OpenChain-Project/Telco-WG/blob/main/OpenChain-Telco-SBOM-Guide_EN.md).

You can check it with the [openchain-telco-sbom-validator](https://pypi.org/project/openchain-telco-sbom-validator/).

## When an SBOM cannot be created

### Versions incompatibility

Running ```pypispdx``` with Python 3.14
```
pypispdx google-ads-reports
Creating SPDX SBOM for PyPI package google-ads-reports
ERROR: Ignored the following versions that require a different python version:
 1.0 Requires-Python >=3.9,<3.13;
 1.0.1 Requires-Python >=3.9,<3.13;
 1.1.0 Requires-Python >=3.9,<3.13;
 1.2.0 Requires-Python >=3.9,<3.13;
 1.2.1 Requires-Python >=3.10,<3.13;
 1.2.2 Requires-Python >=3.10,<3.13;
 1.2.3 Requires-Python >=3.10,<3.13;
 1.3.0 Requires-Python >=3.10,<3.13;
 2.0.0 Requires-Python >=3.12,<3.13;
 2.0.1 Requires-Python >=3.12,<3.13;
 2.0.2 Requires-Python >=3.11,<3.14
ERROR: Could not find a version that satisfies the requirement google-ads-reports (from versions: none)
ERROR: No matching distribution found for google-ads-reports
Cannot create SBOM for google-ads-reports
```

The SBOM cannot be created as ```google-ads-reports``` cannot currently be installed with Python 3.14.
