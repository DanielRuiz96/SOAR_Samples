# Proyecto de Procesamiento de Alertas

Este proyecto es un **script en Python** que procesa alertas en formato JSON/YAML, realiza un flujo completo de análisis y genera resultados usando **plantillas Jinja2**.

El flujo principal sigue cuatro etapas: **Ingestion → Enrichment → Triage → Response**.

## Tecnologías y librerías utilizadas

- Python 3.10+
- [PyYAML](https://pyyaml.org/) → Para manejar archivos YAML
- [Jinja2](https://palletsprojects.com/p/jinja/) → Para plantillas
- Librerías estándar de Python: `os`, `sys`, `datetime`, `json`, `uuid`, `pathlib`

## Flujo de procesamiento

El script procesa las alertas siguiendo estas cuatro etapas:

| Etapa                | Entrada                                      | Qué se hace / Lógica                                                                                                                  | Salida / Resultado                                                             |
| -------------------- | -------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------ |
| **Ingestion**  | Archivo JSON/YAML (`alerts/sentinel.json`) | Se valida que el archivo exista y se carga en memoria. Se normalizan campos básicos  y nombres de campos.                             | Lista de alertas limpias y listas para enriquecimiento.                        |
| **Enrichment** | Alertas cargadas desde Ingestion             | Se agregan datos adicionales:- Conversión de timestamps a UTC - Generación de UUIDs - Enriquecimiento interno según reglas definidas | Alertas enriquecidas con contexto adicional.                                   |
| **Triage**     | Alertas enriquecidas                         | Se aplican reglas de clasificación y priorización:- Severidad - Tipo de evento - Fuente - Posible riesgo                              | Alertas categorizadas y priorizadas para respuesta.                            |
| **Response**   | Alertas triageadas                           | Se generan archivos de salida usando plantillas Jinja2:- JSON estructurado - Reporte en formato deseado                                 | Archivos listos para análisis, informes o integración en otras herramientas. |

## Detalles de cálculo en Triage

| Paso / Etapa   | Entrada                                         | Qué se hace                                 | Cálculo / Lógica                                           | Salida                   |
| -------------- | ----------------------------------------------- | -------------------------------------------- | ------------------------------------------------------------ | ------------------------ |
| Base severity  | `incident["source_alert"]["type"]`            | Asigna puntaje inicial según tipo de alerta | `base_score = BASE_SEVERITY.get(type, 40)`                 | `base_score`           |
| Allowlist      | `incident["indicators"]` + `allowlists.yml` | Marca IOCs y assets permitidos               | `severity_score -= 25` por IOC allowlisted                 | `allowlisted_iocs`     |
| Conteo de IOCs | `incident["indicators"]`                      | Cuenta maliciosos y sospechosos              | `malicious_count`, `suspicious_count`                    | Variables de conteo      |
| Boosts         | Conteo de IOCs                                  | Ajusta score según peligrosidad             | +20 maliciosos, +10 sospechosos, +5 por IOC extra (máx +20) | `severity_score`       |
| Supresión     | Todos los IOCs allowlisted                      | Si todos están permitidos, se suprime       | `severity_score = 0` y `suppressed = True`               | `suppressed`           |
| Bucket         | `severity_score`                              | Clasifica la alerta                          | Según BUCKETS: Low, Medium, High, Critical                  | `severity_label`       |
| MITRE tagging  | Tipo de alerta +`mitre_map.yml`               | Asigna técnicas MITRE relevantes            | Busca coincidencia o usa defaults                            | `incident["mitre"]`    |
| Registro       | Todos los resultados                            | Guardar datos finales                        | Agrega `triage` y `timeline`                             | `incident` actualizado |

## Lógica de decisión para aislar la máquina

- Si el **puntaje de severidad** (`severity_score`) cae en **High (70–89)** o **Critical (90–100)** **y no está suprimido** (`suppressed=False`):

  - La alerta se marca como **requiere acción inmediata**.
  - El SOC **aislar la máquina afectada**.
- Si la severidad es **Medium (40–69)**:

  - Se recomienda **monitoreo intensivo y análisis adicional**.
  - No se aísla automáticamente la máquina, pero se generan reportes para seguimiento.
- Si la severidad es **Low (1–39)** o **Suppressed (0)**:

  - Se registra la alerta para auditoría.
  - No se toman acciones automáticas.

## Salidas del script

- `incident["triage"]`: Diccionario con detalle de la alerta, incluyendo:
  - `base_score`
  - `severity_score`
  - `severity_label` (Low, Medium, High, Critical, Suppressed)
  - Conteo de IOCs maliciosos, sospechosos y allowlisted
  - `tags` y `suppressed`
- `incident["timeline"]`: Lista con etapas del procesamiento y timestamps UTC.
- Archivos generados en la carpeta `output/` usando plantillas Jinja2:
  - JSON con alertas enriquecidas y triageadas
  - Reporte legible para analistas SOC

## Instalación

1. Clonar el repositorio:

```bash
git clone https://github.com/tu-usuario/tu-proyecto.git
cd tu-proyecto
```

2. Crear un entorno virtual:

```bash
python -m venv venv
source venv/bin/activate   # Linux/Mac
venv\Scripts\activate      # Windows
```

3. Instalar dependias:

```bash
pip install -r requirements.txt
```

## Uso

El script espera **un archivo JSON o YAML como argumento**. Por ejemplo:

```bash
python3 main.py alerts/sentinel.json
```

## Estructura del proyecto

SOAR_Samples/

├─ main.py              # Script principal

├─ requirements.txt     # Librerías necesarias

├─ src/                 # Código fuente adicional

├─ configs/             # Archivos de configuración (YAML, JSON)

├─ mocks/               # Datos de prueba / mock

├─ alerts/              # Archivos JSON/YAML de entrada

├─ templates/           # Plantillas Jinja2

└─ output/              # Archivos generados
