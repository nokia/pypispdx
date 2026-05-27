# pypispdx

An SCA tool for creating an SPDX SBOM for a https://pypi.org/ package.

# Usage

```
usage: pypispdx [-h] [--json | --rdf | --xml | --yaml | --spdx3] [--debug] package
```

where “package” is a Python package available on https://pypi.org/

```
options:
  -h, --help            Shows this help message and exits.
  --debug               Enables debug output, including detailed messages and full tracebacks.
  -v, --version         Shows the program version and exits.
  --json                Output the result in SPDX 2.3 JSON format.
  --rdf                 Output the result in SPDX 2.3 RDF format.
  --xml                 Output the result in SPDX 2.3 XML format.
  --yaml                Output the result in SPDX 2.3 YAML format.
  --spdx3               Output the result in SPDX 3.0.1 JSON-LD format.
```

It will create an SPDX 2.3 or 3.0.1 SBOM for the latest available release of the package,
including all transitive dependencies.

Network access is needed when running the tool, it will access <https://pypi.org>
and <https://clearlydefined.io>.

By default, the SPDX 2.3 output will be in tag:value format. The other formats, JSON, RDF,
XML and YAML are available by using the corresponding command-line option.

In SPDX 2.3, the SBOM filename will be ```package-version.spdx``` (plus the corresponding
suffix for the other formats), where the package name will be in lower case,
with underscores and dots replaced by dash.

In SPDX 3.0, it will be ```package-version.spdx3.json``` as
[recommended](https://github.com/spdx/spdx-spec/blob/develop/docs/serializations.md).

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
If not available, it will be ```NOASSERTION```.

If available, the ```PackageChecksum``` will be provided in both SHA256 and MD5.

The ```PackageLicenseConcluded``` and ```PackageLicenseDeclared``` will be given if available on
PyPI or ClearlyDefined.
If not, it will be ```NOASSERTION```. See more details below.

The ```PackageCopyrightText``` will taken from <https://clearlydefined.io> if it is
present there. If not, it will be ```NOASSERTION```.

The [PURL](https://github.com/package-url/purl-spec/) (Package-URL) will be provided:
* in the ```ExternalRef``` field in SPDX 2.3;
* in the ```packageUrl``` property in SPDX 3.0.

## Licenses

First, the licenses will be searched in “license_expression” as specified in
[PEP 639](https://peps.python.org/pep-0639/).

If not available, the licenses will be searched in “license”.

If no “license_expression” and no “license”, the file ```cache``` will be used.

The content of the file is like:
```
# package; license; comment (e.g. pull request)
jsonresolver; BSD-2-Clause AND BSD-3-Clause AND JSON
metrics-miscellany; CC-BY-NC-SA-4.0
multidict; Apache-2.0; https://github.com/aio-libs/multidict/pull/1292
py-tlsh; Apache-2.0 OR BSD-3-Clause
rich-click; MIT
```
If still no license found, we will search in “classifiers”.

The value used in classifiers will be mapped to the corresponding SPDX identifier.

If the classifier is ambiguous, for example:
```
License :: OSI Approved :: GNU General Public License (GPL)
```
a ```LicenseRef-``` is created with that text.

If the license cannot be found on https://pypi.org and in ```cache```, it will be searched on <https://clearlydefined.io>.

When the license is specified with a ```LicenseRef-```, the text of the license
is retreived from the license file and put in the SBOM.

See for example [infinity-grid](https://pypi.org/project/infinity-grid/).

## About PURL specification

The name is case insensitive and lowercased.

Underscore “_” is replaced with dash “-”.

Dot “.” is replaced with dash “-”.

## Compliance

### SPDX 2.3

The SBOM is valid SPDX 2.3.

It is compliant with the [OpenChain Telco SBOM Guide](https://github.com/OpenChain-Project/Telco-WG/blob/main/OpenChain-Telco-SBOM-Guide_EN.md).

You can check it with the [openchain-telco-sbom-validator](https://pypi.org/project/openchain-telco-sbom-validator/).

### SPDX 3.0.1

The SBOM is valid SPDX 3.0.1.

You can check it with:
* https://github.com/spdx/tools-java (in Java)
* https://pypi.org/project/spdx3-validate/ (in Python)

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

# History

What is new in version 0.3.1

* Simpler URIs (remove "SPDXRef-")
* In SPDX 2.3, the create message includes the format
* Update README to indicate that network access is needed when running the tool

What is new in version 0.3.0

* Add an option to create the SBOM in SPDX 3.0.1
* This is experimental

What is new in version 0.2.1

* Control characters are removed from License and Copyright text
* SPDX license list is 3.28
* Better handling of ClearlyDefined failure, SBOM is not created
* Message says that SBOM is created in SPDX 2.3
* Creating SBOM in JSON, RDF, XML or YAML format will not erase existing SBOM in tag:value format

What is new in version 0.2.0

* If license cannot be found in <https://pypi.org>, it will be searched in cache file, then on <https://clearlydefined.io>
* The package Copyright text will taken from <https://clearlydefined.io> if it is present there
