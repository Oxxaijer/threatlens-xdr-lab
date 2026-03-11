from fastapi import FastAPI
from api.elastic_client import ping_elasticsearch, es
from api.config import (
    INDEX_LINUX_EVENTS,
    INDEX_WINDOWS_EVENTS,
    INDEX_SANDBOX_EVENTS,
    INDEX_ALERTS,
)
from api.detector import health_detection_stub, run_detection_engine
from collectors.linux_log_collector import ingest_linux_events
from collectors.windows_event_simulator import ingest_windows_events
from collectors.sandbox_event_generator import ingest_sandbox_events

app = FastAPI(
    title="ThreatLens XDR Lab API",
    version="1.0.0",
    description="Endpoint Threat Research, SIEM Analytics, and Detection Prototype"
)


@app.get("/")
def root():
    return {
        "message": "ThreatLens XDR Lab API is running",
        "platform": "Threat research and endpoint security analytics prototype",
    }


@app.get("/health")
def health():
    elastic_ok = ping_elasticsearch()
    return {
        "api": "ok",
        "elasticsearch": "connected" if elastic_ok else "not connected",
        "detector": health_detection_stub(),
    }


@app.get("/indices")
def list_indices():
    try:
        indices = es.indices.get_alias(index="*")
        return {"indices": list(indices.keys())}
    except Exception as e:
        return {"error": str(e)}


@app.get("/stats")
def stats():
    try:
        def safe_count(index_name: str) -> int:
            if es.indices.exists(index=index_name):
                response = es.count(index=index_name)
                return response.get("count", 0)
            return 0

        return {
            "linux_events": safe_count(INDEX_LINUX_EVENTS),
            "windows_events": safe_count(INDEX_WINDOWS_EVENTS),
            "sandbox_events": safe_count(INDEX_SANDBOX_EVENTS),
            "alerts": safe_count(INDEX_ALERTS),
        }
    except Exception as e:
        return {"error": str(e)}


@app.get("/alerts")
def get_alerts():
    try:
        if not es.indices.exists(index=INDEX_ALERTS):
            return []

        response = es.search(
            index=INDEX_ALERTS,
            body={
                "size": 100,
                "sort": [{"timestamp": {"order": "desc"}}]
            },
        )

        return [hit["_source"] for hit in response["hits"]["hits"]]
    except Exception as e:
        return {"error": str(e)}


@app.post("/ingest/linux")
def ingest_linux():
    return ingest_linux_events()


@app.post("/ingest/windows")
def ingest_windows():
    return ingest_windows_events()


@app.post("/ingest/sandbox")
def ingest_sandbox():
    return ingest_sandbox_events()


@app.post("/ingest/all")
def ingest_all():
    linux_result = ingest_linux_events()
    windows_result = ingest_windows_events()
    sandbox_result = ingest_sandbox_events()

    return {
        "linux": linux_result,
        "windows": windows_result,
        "sandbox": sandbox_result,
    }


@app.post("/detect")
def detect_threats():
    return run_detection_engine()