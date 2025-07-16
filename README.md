## Project Overview

This Cyberg Academy cybersecurity course repository focused on Threat Hunting and Sigma rule development ("curso-th-sigma"). The project is educational in nature, teaching threat hunting methodologies and detection rule creation using the Sigma standard.

## Repository Structure

### Lab Configuration (01-Configuracion-del-Lab/)
- `elastic_upload_events.py` - Script to upload threat hunting lab events to Elasticsearch
- `cyberg-th-lab-events.json` - Aggregated lab events for analysis

### Threat Intelligence (02-Introduccion-al-TH/)
- `fetch_company_threats.py` - Interactive script to analyze APT threats relevant to specific companies based on sectors and countries
- `search_sigma_rules_by_threat.py` - Script to search Sigma rules by specific threat indicators (groups, tools, CVEs, tactics, techniques)

### Sigma Rules Development (03-Sigma/)
- `rules/` - Contains example Sigma rules and templates
  - `rule_template.yaml` - Comprehensive template with all possible Sigma rule fields and documentation
  - `rule_example1.yml` - Basic Windows Defender rule example
- `pipelines/` - Custom field mapping examples for log normalization
- `sigma_rule_check_similarity.py` - Script to check similarity between Sigma rules

### Challenge Section (04-Reto/)
- TODO

## Important Notes
- This is an educational cybersecurity project focused on defensive techniques
- Lab events are synthetic and designed for training purposes
- Sigma rules follow community standards and MITRE ATT&CK framework mapping
- All threat data comes from public sources (ThaiCERT API)