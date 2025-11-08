# Proyecto de Procesamiento de Alertas / Alert Processing Project

Este proyecto es un **script en Python** que procesa alertas en formato JSON/YAML, realiza un flujo completo de análisis y genera resultados usando **plantillas Jinja2**.
This project is a **Python script** that processes alerts in JSON/YAML format, performs a complete analysis flow, and generates results using **Jinja2 templates**.

El flujo principal sigue cuatro etapas: **Ingestion → Enrichment → Triage → Response**.
The main workflow follows four stages: **Ingestion → Enrichment → Triage → Response**.

## Tecnologías y librerías utilizadas / Technologies and Libraries Used

- Python 3.10+
- [PyYAML](https://pyyaml.org/) → Para manejar archivos YAML / For handling YAML files
- [Jinja2](https://palletsprojects.com/p/jinja/) → Para plantillas / For templates
- Librerías estándar de Python / Standard Python libraries: `os`, `sys`, `datetime`, `json`, `uuid`, `pathlib`

## Flujo de procesamiento / Processing Flow

| Etapa / Stage        | Entrada / Input                              | Qué se hace / Logic                                                                                                | Salida / Output                               |
| -------------------- | -------------------------------------------- | ------------------------------------------------------------------------------------------------------------------- | --------------------------------------------- |
| **Ingestion**  | Archivo JSON/YAML (`alerts/sentinel.json`) | Se valida que el archivo exista y se carga en memoria. / Validates and loads the file into memory.                  | Lista de alertas limpias / Clean alerts list  |
| **Enrichment** | Alertas cargadas                             | Se agregan datos adicionales: timestamps, UUIDs, enriquecimiento interno. / Adds timestamps, UUIDs, and extra data. | Alertas enriquecidas / Enriched alerts        |
| **Triage**     | Alertas enriquecidas                         | Se aplican reglas de clasificación y priorización. / Applies classification and prioritization rules.             | Alertas priorizadas / Prioritized alerts      |
| **Response**   | Alertas triageadas                           | Se generan reportes usando plantillas Jinja2. / Generates reports using Jinja2 templates.                           | Archivos listos para análisis / Output files |

## Detalles de cálculo en Triage / Triage Calculation Details

| Paso / Step                | Entrada / Input                                 | Qué se hace / What it does                                                | Cálculo / Logic                             | Salida / Output                           |
| -------------------------- | ----------------------------------------------- | -------------------------------------------------------------------------- | -------------------------------------------- | ----------------------------------------- |
| Base severity              | `incident["source_alert"]["type"]`            | Asigna puntaje inicial / Assigns base score                                | `base_score = BASE_SEVERITY.get(type, 40)` | `base_score`                            |
| Allowlist                  | `incident["indicators"]` + `allowlists.yml` | Marca IOCs permitidos / Marks allowed IOCs                                 | `severity_score -= 25` por IOC permitido   | `allowlisted_iocs`                      |
| Conteo de IOCs / IOC Count | `incident["indicators"]`                      | Cuenta maliciosos y sospechosos / Counts malicious and suspicious IOCs     | Variables de conteo / Counting vars          | `malicious_count`, `suspicious_count` |
| Boosts                     | Conteo de IOCs                                  | Ajusta score / Adjusts score                                               | +20 maliciosos, +10 sospechosos              | `severity_score`                        |
| Supresión / Suppression   | Todos IOCs allowlisted                          | Si todos están permitidos, se suprime / Suppresses if all are allowlisted | `severity_score = 0`                       | `suppressed`                            |
| Bucket                     | `severity_score`                              | Clasifica la alerta / Classifies alert                                     | Según BUCKETS / According to BUCKETS        | `severity_label`                        |
| MITRE tagging              | Tipo de alerta / Alert type                     | Asigna técnicas MITRE / Maps MITRE techniques                             | Busca coincidencias / Matches mappings       | `incident["mitre"]`                     |
| Registro / Logging         | Todos los resultados / All results              | Guarda resultados finales / Saves final data                               | Agrega `triage` y `timeline`             | `incident` actualizado                  |

## Lógica para aislar máquina / Machine Isolation Logic

### Alta o Crítica / High or Critical

- **Condición / Condition**:
  Si el **puntaje de severidad** (`severity_score`) es **High (70–89)** o **Critical (90–100)** y no está suprimido (`suppressed=False`).
  *If the **severity score** (`severity_score`) is **High (70–89)** or **Critical (90–100)** and it is not suppressed (`suppressed=False`).*
- **Acción / Action:**
  → Se marca como **acción inmediata / immediate action required**
  → El SOC debe **aislar la máquina afectada / isolate the affected machine**

### Media / Medium

- **Condición / Condition**:
  Si la severidad es **Medium (40–69)**.
  *If the severity is **Medium (40–69)**.*
- **Acción / Action:**
  → Monitoreo intensivo / intensive monitoring
  → No se aísla automáticamente / no auto-isolation

### Baja o Suprimida / Low or Suppressed

- **Condición / Condition:**
  Si la severidad es **Low (1–39)** o **Suppressed (0)**.
  *If the severity is **Low (1–39)** or **Suppressed (0)**.*
- **Acción / Action:**
  → Solo se registra para auditoría / logged for audit
  → No se toman acciones automáticas / no automatic actions

## Salidas del script / Script Outputs

- `incident["triage"]`:Contiene / Contains:

  - `base_score`
  - `severity_score`
  - `severity_label` (Low, Medium, High, Critical, Suppressed)
  - Conteo de IOCs / IOC counts
  - `tags` y `suppressed`
- `incident["timeline"]`:Lista con etapas del procesamiento y timestamps UTC /List of processing stages and UTC timestamps.
- Archivos generados en `output/` / Files generated in `output/`:

  - JSON con alertas triageadas / JSON with triaged alerts
  - Reporte legible para analistas SOC / Readable report for SOC analysts

## Instalación / Installation

1. Clonar el repositorio / Create virtual environment:

```bash
git clone https://github.com/DanielRuiz96/SOAR_Samples.git
cd SOAR_Samples
```

2. Crear un entorno virtual / Create virtual environment:

```bash
python -m venv venv
source venv/bin/activate   # Linux/Mac
venv\Scripts\activate      # Windows
```

3. Instalar dependias / Install dependencies:

```bash
pip install -r requirements.txt
```

## Uso / Usage

El script espera **un archivo JSON o YAML como argumento**. Por ejemplo:

The script expects  **a JSON or YAML file as an argument** .For Example:

```bash
python3 main.py alerts/sentinel.json
```

## Estructura del proyecto / Project Structure

```bash
SOAR_Samples/
├─ main.py              # Script principal / Main script
├─ requirements.txt     # Librerías necesarias / Required libraries
├─ src/                 # Código fuente adicional / Source code
├─ configs/             # Archivos de configuración / Config files
├─ mocks/               # Datos de prueba / Mock data
├─ alerts/              # Archivos JSON/YAML de entrada / Input alerts
├─ templates/           # Plantillas Jinja2 / Jinja2 templates
└─ output/              # Archivos generados / Output files
```
