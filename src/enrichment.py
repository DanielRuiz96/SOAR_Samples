import os
import json
import yaml
from datetime import datetime, timezone

# --- Prioridad para determinar el verdict final ---
VERDICT_PRIORITY = {
    "malicious": 4,
    "suspicious": 3,
    "clean": 2,
    "unknown": 1
}
# --- Utilidades generales ---
def load_yaml(path: str) -> dict:
    """Carga segura de archivos YAML."""
    try:
        with open(path, "r") as f:
            return yaml.safe_load(f) or {}
    except Exception as e:
        print(f"⚠️ Error al leer {path}: {e}")
        return {}

def determine_verdict(entry: dict, provider: str) -> tuple[str, int]:
    """Normaliza el verdict y el score según la fuente TI."""
    verdict, score = "unknown", 0

    if provider == "anomali":
        verdict = entry.get("risk", "unknown").lower()
        score = entry.get("confidence", 0)
    elif provider == "defender_ti":
        verdict = entry.get("reputation", "unknown").lower()
        score = entry.get("score", 0)
    elif provider == "reversinglabs":
        verdict = entry.get("classification", "unknown").lower()
        score = entry.get("score", 0)

    return verdict, score

def load_mock_data(base_path: str, provider: str) -> list:
    """Carga los mocks del proveedor específico."""
    ti_entries = []
    if base_path.startswith("file://"):
        base_path = base_path.replace("file://", "")

    if not os.path.exists(base_path):
        print(f"Carpeta de mocks no encontrada para {provider}: {base_path}")
        return []

    for root, _, files in os.walk(base_path):
        for filename in files:
            if not filename.endswith(".json"):
                continue
            if filename.startswith(provider):
                try:
                    with open(os.path.join(root, filename), "r") as f:
                        ti_entries.append(json.load(f))
                except Exception as e:
                    print(f"Error al leer mock {filename}: {e}")
    return ti_entries

def match_ioc(entry: dict, indicator: dict) -> bool:
    """Determina si un mock corresponde al indicador actual."""
    value = indicator["value"]
    for key, val in entry.items():
        if isinstance(val, str) and val.lower() == value.lower():
            return True
    return False

def enrich_incident(incident: dict,connectors_path: str = "configs/connectors.yml") -> dict:
    """Enriquece los indicadores del incidente usando los proveedores del YAML."""

    connectors = load_yaml(connectors_path)
    providers = connectors.get("providers", {})

    if not providers:
        print("⚠️ No se encontraron proveedores en connectors.yml")
        return incident

    # Cargar todos los mocks de los proveedores definidos
    ti_data = {}
    for provider, cfg in providers.items():
        base_url = cfg.get("base_url", "")
        ti_data[provider] = load_mock_data(base_url, provider)

    # --- Enriquecimiento de los indicadores ---
    for indicator in incident.get("indicators", []):
        best_verdict = "unknown"
        all_scores = []
        all_sources = []

        for provider, entries in ti_data.items():
            for entry in entries:
                if match_ioc(entry, indicator):
                    verdict, score = determine_verdict(entry, provider)
                    all_sources.append(provider)
                    all_scores.append(score)
                    if VERDICT_PRIORITY[verdict] > VERDICT_PRIORITY[best_verdict]:
                        best_verdict = verdict

        if all_sources:
            avg_score = int(sum(all_scores) / len(all_scores))
            indicator["risk"] = {
                "verdict": best_verdict,
                "score": avg_score,
                "sources": all_sources
            }

    # Registrar la etapa en el timeline
    incident["timeline"].append({
        "stage": "enrich",
        "ts": datetime.now(timezone.utc).isoformat(),
        "details": f"Indicators enriched using connectors from {connectors_path}"
    })

    return incident
