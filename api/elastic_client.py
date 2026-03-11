from elasticsearch import Elasticsearch
from api.config import ELASTICSEARCH_URL

es = Elasticsearch(ELASTICSEARCH_URL)


def ping_elasticsearch() -> bool:
    try:
        return es.ping()
    except Exception:
        return False