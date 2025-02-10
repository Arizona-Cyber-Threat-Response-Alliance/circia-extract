
# CIRCIA Extract

CIRCIA Extract is a Python script designed to extract and summarize indicators from PDF files, specifically tailored for CIRCIA (Cyber Incident Reporting for Critical Infrastructure Act) incident reports.

## Features

- Extracts content from PDF files
- Identifies and categorizes various types of indicators (IOCs)
- Provides a summary and visualization of extracted indicators
- Supports a domain whitelist to exclude specific indicators
- Extracts and displays the incident description
- Option to display raw extracted content

## Requirements

- Python 3.6+
- pypdf library

## Installation

1. Clone this repository or download the `circia-extract.py` file.
2. Install the required library:

```
pip install pypdf
```

## Usage

Run the script from the command line with the following syntax:

```
python circia-extract.py -f <path_to_pdf_file> [--raw] [--add-whitelist <domain1> <domain2> ...]
```

### Arguments

- `-f, --file`: (Required) Path to the PDF file to analyze
- `--raw`: (Optional) Display raw extracted content
- `--add-whitelist`: (Optional) Add domains to the whitelist

### Example

```
python circia-extract.py -f incident_report.pdf --add-whitelist example.com trusted-domain.com
```

## Output

The script provides the following output:

1. Summary and visualization of extracted indicators
2. Lists of extracted indicators by type
3. Whitelisted domains
4. Incident description (if found in the PDF)
5. Raw extracted content (if `--raw` option is used)

## Supported Indicator Types

- Hostnames
- IPv4 addresses
- Email addresses
- MD5 hashes
- URLs
- IPv6 addresses
- SHA-1 hashes
- SHA-256 hashes
- ASNs
- Registry key values
- User agents

## Customization

You can modify the `whitelist_domains` set in the script to add or remove domains that should be excluded from the extracted indicators.

## Autho
Community Driven Project