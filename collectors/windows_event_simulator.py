import json
from pathlib import Path
from api.elastic_client import es
from api.config import INDEX_WINDOWS_EVENTS

BASE_DIR = Path(__file__).resolve().parent.parent
WINDOWS_EVENTS_FILE = BASE_DIR / "analytics" / "sample_events" / "windows_events.json"


def load_windows_events():
    if not WINDOWS_EVENTS_FILE.exists():
        return []

    with open(WINDOWS_EVENTS_FILE, "r", encoding="utf-8") as file:
        return json.load(file)


def ingest_windows_events():
    events = load_windows_events()

    indexed = 0
    errors = []

    for event in events:
        try:
            es.index(index=INDEX_WINDOWS_EVENTS, document=event)
            indexed += 1
        except Exception as e:
            errors.append(str(e))

    return {
        "source": "windows",
        "events_loaded": len(events),
        "events_indexed": indexed,
        "errors": errors,
    }