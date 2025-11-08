import yaml
from datetime import datetime, timezone

# --- Configuración base ---
BASE_SEVERITY = {
    "malware": 70,
    "phishing": 60,
    "beaconing": 65,
    "credentialaccess": 75,
    "c2": 80,
    "unknown": 40
}

BUCKETS = [
    (0, 0, "Suppressed"),
    (1, 39, "Low"),
    (40, 69, "Medium"),
    (70, 89, "High"),
    (90, 100, "Critical")
]

def load_yaml(path: str) -> dict:
    """Carga un archivo YAML de forma segura."""
    try:
        with open(path, "r") as f:
            return yaml.safe_load(f) or {}
    except FileNotFoundError:
        print(f"Archivo no encontrado: {path}")
        return {}
    except Exception as e:
        print(f"Error al leer {path}: {e}")
        return {}

def clamp(value: int, min_val: int = 0, max_val: int = 100) -> int:
    """Limita la severidad a un rango permitido."""
    return max(min_val, min(max_val, value))

def get_bucket_label(score: int) -> str:
    """Devuelve la etiqueta del bucket según el puntaje."""
    for low, high, label in BUCKETS:
        if low <= score <= high:
            return label
    return "Unknown"

def perform_triage(incident: dict,allowlists_path: str = "configs/allowlists.yml",mitre_path: str = "configs/mitre_map.yml") -> dict:
    """Calcula la severidad del incidente y realiza tagging MITRE."""

    allowlists = load_yaml(allowlists_path)
    mitre_map = load_yaml(mitre_path)

    # --- 1️. Base severity por tipo de alerta ---
    alert_type = incident.get("source_alert", {}).get("type", "Unknown").lower()
    base_score = BASE_SEVERITY.get(alert_type, BASE_SEVERITY["unknown"])
    severity_score = base_score
    tags = []
    suppressed = False

    # --- 2️. Allowlist preparation ---
    allowlisted_iocs = set()
    allowlisted_assets = set()

    for ioc_type, values in allowlists.get("indicators", {}).items():
        allowlisted_iocs.update(v.lower() for v in values)
    allowlisted_assets.update(v.lower() for v in allowlists.get("assets", {}).get("device_ids", []))

    # --- 3️.Intel boosts ---
    malicious_count = 0
    suspicious_count = 0
    allowlisted_count = 0

    for indicator in incident.get("indicators", []):
        val = indicator["value"].lower()

        # Allowlist suppression
        if val in allowlisted_iocs:
            indicator["allowlisted"] = True
            allowlisted_count += 1
            tags.append("allowlisted")
            severity_score -= 25
            continue

        verdict = indicator.get("risk", {}).get("verdict", "unknown").lower()

        if verdict == "malicious":
            malicious_count += 1
        elif verdict == "suspicious":
            suspicious_count += 1

    # --- 4️. Aplicar boosts por verdicts ---
    if malicious_count > 0:
        severity_score += 20
    elif suspicious_count > 0:
        severity_score += 10

    # +5 por IOC adicional, cap +20
    extra_iocs = max(0, (malicious_count + suspicious_count) - 1)
    severity_score += min(20, extra_iocs * 5)

    # --- 5️. Si todos los IOCs están permitidos, suprimir ---
    total_iocs = len(incident.get("indicators", []))
    if total_iocs > 0 and allowlisted_count == total_iocs:
        severity_score = 0
        suppressed = True
        tags.append("suppressed")

    # --- 6️. Clamp & bucket ---
    severity_score = clamp(int(severity_score))
    severity_label = get_bucket_label(severity_score)

    # --- 7️. MITRE tagging ---
    mitre_techniques = []
    mitre_types = mitre_map.get("types", {})

    alert_type_lower = alert_type.lower()

    for key in mitre_types.keys():
        if key.lower() == alert_type_lower:
            mitre_techniques = mitre_types[key]
            break

    # Si no encuentra coincidencia, usar defaults
    if not mitre_techniques:
        mitre_techniques = mitre_map.get("defaults", [])
    
    incident["mitre"] = mitre_techniques

    # --- 8️. Guardar resultados ---
    incident["triage"] = {
        "base_score": base_score,
        "severity_score": severity_score,
        "severity_label": severity_label,
        "malicious_iocs": malicious_count,
        "suspicious_iocs": suspicious_count,
        "allowlisted_iocs": allowlisted_count,
        "tags": list(set(tags)),
        "suppressed": suppressed
    }

    incident["timeline"].append({
        "stage": "triage",
        "ts": datetime.now(timezone.utc).isoformat(),
        "details": f"Triage completed. Score={severity_score} ({severity_label}), Suppressed={suppressed}"
    })

    return incident
