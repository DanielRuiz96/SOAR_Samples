import os
import json
import yaml
from datetime import datetime, timezone
from jinja2 import Template

def load_yaml(path: str) -> dict:
    """Carga segura de archivos YAML."""
    try:
        with open(path, "r") as f:
            return yaml.safe_load(f) or {}
    except Exception as e:
        print(f"Error al leer {path}: {e}")
        return {}

def execute_response(incident: dict, configs_path: str = "configs", out_path: str = "out") -> dict:
    """Ejecuta la fase de respuesta y genera los archivos de salida (simulada)."""

    # --- Preparar rutas de salida ---
    os.makedirs(f"{out_path}/incidents", exist_ok=True)
    os.makedirs(f"{out_path}/summaries", exist_ok=True)
    os.makedirs(out_path, exist_ok=True)

    # --- Cargar configuración ---
    connectors = load_yaml(f"{configs_path}/connectors.yml")
    allowlists = load_yaml(f"{configs_path}/allowlists.yml")

    edr_base = connectors.get("edr", {}).get("base_url", "")
    allowlisted_devices = [
        d.lower() for d in allowlists.get("assets", {}).get("device_ids", [])
    ]

    severity = incident.get("triage", {}).get("severity_score", 0)
    device_id = incident.get("asset", {}).get("device_id", "")
    device_id_lower = device_id.lower() if isinstance(device_id, str) else ""
    incident_id = incident.get("incident_id")
    asset_ip = incident.get("asset", {}).get("ip", "")
    asset_hostname = incident.get("asset", {}).get("hostname", "")

    actions = []
    now = datetime.now(timezone.utc).isoformat()

    # --- Reglas de respuesta (simuladas) ---
    if severity >= 70 and device_id_lower and device_id_lower not in allowlisted_devices:
        action = {
            "type": "isolate",
            "target": f"device:{device_id}",
            "result": "isolated",
            "asset_ip": asset_ip,
            "asset_hostname": asset_hostname,
            "ts": now
        }

        # Simulación: no hay request real, solo log y registro
        print(f"(Simulado) Acción de aislamiento enviada a {edr_base}/isolate "
              f"para device_id={device_id}, hostname={asset_hostname}, ip={asset_ip}, incidente={incident_id}")

        actions.append(action)

        # Registrar en isolation.log (añadido ip y hostname)
        with open(f"{out_path}/isolation.log", "a") as log:
            log.write(f"{now} isolate device_id={device_id} hostname={asset_hostname} ip={asset_ip} "
                      f"incident={incident_id} result=isolated\n")

    # --- Actualizar incidente ---
    incident["actions"].extend(actions)
    incident["timeline"].append({
        "stage": "respond",
        "ts": now,
        "details": f"Response executed (simulated). Actions={len(actions)}"
    })

    # --- Guardar JSON del incidente ---
    with open(f"{out_path}/incidents/{incident_id}.json", "w") as f:
        json.dump(incident, f, indent=2)

    # --- Crear resumen Markdown (analyst report) ---
    template_path = os.path.join("templates", "incident_report.md.j2")
    with open(template_path, "r") as f:
        template = Template(f.read())

    md_output = template.render(incident=incident)
    with open(f"{out_path}/summaries/{incident_id}.md", "w") as f:
        f.write(md_output.strip() + "\n")

    print(f"Reporte Markdown generado en {out_path}/summaries/{incident_id}.md")

    return incident
