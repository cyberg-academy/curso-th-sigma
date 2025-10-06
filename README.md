# Threat Hunting Avanzado con Sigma

Repositorio oficial del curso de [Cyberg Academy - Threat Hunting Avanzado con Sigma](https://cyberg-academy.io/curso-th-avanzando-sigma).

## Estructura del Repositorio

### 01-Configuracion-del-Lab
- `elastic_upload_events.py` - Script para subir eventos de laboratorio a Elasticsearch

### 02-Introduccion-al-TH
- `fetch_company_threats.py` - Script para analizar amenazas APT relevantes por sector y país
- `search_sigma_rules_by_threat.py` - Script para buscar reglas Sigma por indicadores de amenaza

### 03-Sigma
- `rules/` - Reglas Sigma de ejemplo y plantillas
- `pipelines/` - Ejemplos de mapeo de campos para normalización de logs
- `sigma_rule_check_similarity.py` - Script para verificar similitud entre reglas Sigma
- `sigma_to_eql_converter.py` - Conversor de reglas Sigma a EQL
