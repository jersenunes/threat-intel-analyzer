# Threat Intel Analyzer

## Overview
**Threat Intel Analyzer** is a Python-based command-line tool for automated enrichment of Indicators of Compromise (IOCs) and files using multiple threat intelligence sources.

This project simulates real-world SOC and SOAR workflows, where automated systems or analysts must enrich alerts and artifacts with external intelligence. It supports querying multiple APIs and returns structured JSON output for easy integration into automation pipelines, SIEM enrichment, or SOAR playbooks.

---

## Supported Threat Intelligence Integrations
The tool currently integrates with the following services:

- **VirusTotal** — enrichment of IPs, domains, URLs, hashes, and file submissions
- **AbuseIPDB** — reputation analysis for IP addresses
- **OTX AlienVault** — community-driven threat intelligence for multiple IOC types

---

## Supported Input Types
The analyzer supports enrichment for:

- IP addresses
- Domains
- URLs
- File hashes
- Local files for submission and analysis
- JSON files containing multiple indicators

---

## Installation
Clone the repository and install dependencies:

```bash
git clone https://github.com/jersenunes/threat-intel-analyzer.git
cd threat-intel-analyzer
pip install -r requirements.txt
```

---

## Configuration
API keys and usage instructions are defined in the `settings.py` file.

Follow the instructions inside this file to properly configure access to the supported Threat Intelligence providers before running the tool.

---

## Usage
The script is executed via command line and accepts one input type per execution.

**Providers are optional.**

If no provider is specified, the tool automatically queries all available providers
that support the given indicator type.

If a provider is specified, only that provider will be used for enrichment.

### Examples

```bash
python main.py json=examples/inputs_file.json
python main.py ip=1.1.1.1
python main.py ip=1.1.1.1 provider=abuse
python main.py domain=google.com provider=virustotal
python main.py url=https://www.youtube.com provider=otx
python main.py hash=23792BDD1136C3A69AD6A5BDC0914A45 provider=alienvault
python main.py file=examples/file.pdf provider=vt

```

Each execution queries the configured threat intelligence sources and returns a structured JSON response.

---

## Output
All enrichment results are returned in **JSON format**, designed to be consumed by:

- SOAR playbooks
- SIEM enrichment pipelines
- Automated alert triage workflows
- Case management and response systems

---

## Architecture and Design
This project was built with security automation and SOAR use cases in mind:

- Modular structure separating input handling and enrichment logic
- API-driven enrichment workflow using multiple intelligence sources
- Consistent JSON output for automation and orchestration platforms
- Easy extensibility for adding new Threat Intelligence providers

---

## Use Cases
- IOC enrichment during incident response
- Automated alert triage in SOC environments
- Proof of concept for SOAR integrations
- Learning and practicing security automation with Python

---

## Project Status
- Fully functional
- Developed as a personal automation and learning project
- Designed to reflect realistic SOC and SOAR enrichment scenarios

---

## Disclaimer
This project is intended for educational and professional demonstration purposes only.  
It does not replace commercial SOAR or Threat Intelligence platforms.

---

## About the Author
Security-focused professional with hands-on experience in **Security Automation**, **SOAR concepts**, and **Python-based integrations**.
This project reflects real-world challenges commonly faced by SOC and Automation Engineers.
