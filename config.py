from dotenv import load_dotenv
import os

# Load environment variables
load_dotenv()

# RAG 설정
ENABLE_RAG = os.getenv('ENABLE_RAG', 'true').lower() == 'true'

# Elasticsearch 설정
ELASTICSEARCH_HOST = "localhost"
ELASTICSEARCH_PORT = 9200
INDEX_NAME = "documents"

# Ollama 설정
OLLAMA_HOST = "http://localhost:11434"
MODEL_NAME = "qwen3:32b"  # 또는 다른 설치된 모델을 선택할 수 있습니다