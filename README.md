# Threat Intel Analyzer

## Overview
**Threat Intel Analyzer** is a Python-based project focused on automating the enrichment of Indicators of Compromise (IOCs) and files using multiple Threat Intelligence sources.

The project simulates a real-world SOC and SOAR scenario, where analysts or automated playbooks must query external Threat Intelligence platforms to enrich alerts, incidents, or suspicious artifacts in an efficient and structured way.

This repository was developed as a functional personal project with strong emphasis on **Security Automation**, **API integrations**, and **SOAR-oriented workflows**.

---

## Key Features
- Automated enrichment for multiple IOC types
- Command-line execution, suitable for automation and orchestration
- Structured JSON output, easy to consume by other systems
- Modular and extensible design for future integrations

---

## Supported Inputs
The tool currently supports enrichment for:

- IP addresses
- Domains
- URLs
- File hashes
- Local files
- JSON files containing multiple indicators

---

## Usage
The script is executed via command line and accepts one input type per execution.

### Examples
```bash
python main.py ip=1.1.1.1
python main.py domain=google.com
python main.py url=https://www.youtube.com
python main.py hash=23792BDD1136C3A69AD6A5BDC0914A45
python main.py file=examples/file.pdf
python main.py json=examples/inputs_file.json
```

---

## Output
All enrichments are returned in JSON format, making the output suitable for:

- SOAR playbooks
- SIEM enrichment pipelines
- Further automated processing
- Integration with case management or alerting systems

---

## Architecture and Design
This project was designed with SOAR use cases in mind:

- Clear separation between input parsing and enrichment logic
- API-driven enrichment workflow
- Output format aligned with automation and orchestration platforms
- Easy to extend with additional Threat Intelligence sources without major refactoring

---

## Use Cases
- IOC enrichment during incident response
- Automated triage of alerts in SOC environments
- Proof of concept for SOAR integrations
- Learning and practicing security automation with Python

---

## Project Status
- Functional and actively evolving
- Built as a personal study and hands-on automation project
- Designed to reflect real-world SOC and SOAR scenarios

---

## Disclaimer
This project is intended for educational and professional demonstration purposes.
It does not replace commercial SOAR or Threat Intelligence platforms.

---

## About the Author
Security-focused professional with hands-on experience in **Security Automation**, **SOAR concepts**, and **Python-based integrations**.
This project reflects real-world challenges commonly faced by SOC and Automation Engineers.