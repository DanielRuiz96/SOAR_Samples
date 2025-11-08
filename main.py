import sys
from src.ingestion import ingest_alert
from src.enrichment import enrich_incident
from src.triage import perform_triage
from src.response import execute_response

def main():
    # --- Validar argumento ---
    if len(sys.argv) != 2:
        print("Usage: python main.py <alert_path>")
        sys.exit(1)

    alert_path = sys.argv[1]

    # --- Ingestión del alerta ---
    try:
        incident = ingest_alert(alert_path)
        print("\n Alert ingested and normalized successfully")
    except FileNotFoundError:
        print(f"File not found: {alert_path}")
        sys.exit(1)
    except Exception as e:
        print(f"Error processing alert: {e}")
        sys.exit(1)

    # --- Enriquecimiento ---
    try:
        incident = enrich_incident(incident, connectors_path="configs/connectors.yml")
        print("\n Incident enriched using connectors.yml")
    except Exception as e:
        print(f"Enrichment failed: {e}")

    # --- Triage ---
    try:
        incident = perform_triage(incident)
        print(f"\n Triage completed: {incident['triage']['severity_label']} ({incident['triage']['severity_score']})")
    except Exception as e:
        print(f"Triage failed: {e}")

    # --- Respuesta ---
    try:
        incident = execute_response(incident)
        print(f"\nResponse executed and files generated successfully")
    except Exception as e:
        print(f"⚠️ Response phase failed: {e}")

    # --- Resultado final ---
    print("\nFinal Incident Data:\n")
    print(incident)


if __name__ == "__main__":
    main()
