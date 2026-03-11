import json
from pathlib import Path
from api.elastic_client import es
from api.config import INDEX_SANDBOX_EVENTS

BASE_DIR = Path(__file__).resolve().parent.parent
SANDBOX_EVENTS_FILE = BASE_DIR / "analytics" / "sample_events" / "sandbox_events.json"


def load_sandbox_events():
    if not SANDBOX_EVENTS_FILE.exists():
        return []

    with open(SANDBOX_EVENTS_FILE, "r", encoding="utf-8") as file:
        return json.load(file)


def ingest_sandbox_events():
    events = load_sandbox_events()

    indexed = 0
    errors = []

    for event in events:
        try:
            es.index(index=INDEX_SANDBOX_EVENTS, document=event)
            indexed += 1
        except Exception as e:
            errors.append(str(e))

    return {
        "source": "sandbox",
        "events_loaded": len(events),
        "events_indexed": indexed,
        "errors": errors,
    }