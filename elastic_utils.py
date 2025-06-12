from elasticsearch import Elasticsearch
from config import ELASTICSEARCH_HOST, ELASTICSEARCH_PORT, INDEX_NAME

def get_elasticsearch_client():
    """generate Elasticsearch client"""
    return Elasticsearch(f"http://{ELASTICSEARCH_HOST}:{ELASTICSEARCH_PORT}")

def create_index(client):
    """create index for storing documents"""
    index_body = {
        "mappings": {
            "properties": {
                "content": {"type": "text"},
                "embedding": {"type": "dense_vector", "dims": 2048},
                "metadata": {"type": "object"}
            }
        }
    }
    
    if not client.indices.exists(index=INDEX_NAME):
        client.indices.create(index=INDEX_NAME, body=index_body)
        print(f"Created index: {INDEX_NAME}")
    else:
        print(f"Index {INDEX_NAME} already exists") 