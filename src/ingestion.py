import json
import uuid
from datetime import datetime, timezone
from pathlib import Path

def ingest_alert(alert_path: str) -> dict:
    """Lee una alerta JSON y la convierte a un formato de incidente normalizado."""

    path = Path(alert_path)
    if not path.exists():
        raise FileNotFoundError(f"Alert file not found: {path}")

    # Leer el archivo JSON
    with open(path, "r") as f:
        alert = json.load(f)

    # Extraer indicadores (normalizados)
    indicators = []
    for ioc_type, values in alert.get("indicators", {}).items():
        for value in values:
            indicators.append({
                "type": ioc_type,
                "value": value,
                "risk": {"verdict": "unknown", "score": 0, "sources": []},
                "allowlisted": False
            })

    # Crear estructura base del incidente
    incident = {
        "incident_id": str(uuid.uuid4()),
        "source_alert": alert,
        "asset": {
            "device_id": alert.get("asset", {}).get("device_id"),
            "hostname": alert.get("asset", {}).get("hostname"),
            "ip": alert.get("asset", {}).get("ip"),
        },
        "indicators": indicators,
        "triage": None,
        "mitre": None,
        "actions": [],
        "timeline": [
            {
                "stage": "ingest",
                "ts": datetime.now(timezone.utc).isoformat(),
                "details": f"Alert ingested and normalized from {alert_path}",
            }
        ],
    }

    return incident
