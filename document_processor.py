from typing import List, Dict, Any
import os
import numpy as np
from elastic_utils import get_elasticsearch_client, create_index
from ollama_utils import OllamaClient
from config import INDEX_NAME

class DocumentProcessor:
    def __init__(self):
        self.es_client = get_elasticsearch_client()
        self.ollama_client = OllamaClient()
        # create index if not exists
        create_index(self.es_client)
        
    def reduce_embedding_dimension(self, embedding: List[float], target_dim: int = 2048) -> List[float]:
        """reduce embedding dimension"""
        if len(embedding) <= target_dim:
            return embedding
            
        # split embedding into chunks and calculate average
        chunks = np.array_split(np.array(embedding), target_dim)
        reduced = [float(chunk.mean()) for chunk in chunks]
        return reduced
        
    def process_text(self, text: str, metadata: Dict[str, Any] = None) -> Dict[str, Any]:
        """process text and generate embedding"""
        embedding = self.ollama_client.generate_embedding(text)
        # reduce embedding dimension
        reduced_embedding = self.reduce_embedding_dimension(embedding)
        
        document = {
            "content": text,
            "embedding": reduced_embedding,
            "metadata": metadata or {}
        }
        
        return document
    
    def index_document(self, document: Dict[str, Any]) -> None:
        """save document to Elasticsearch"""
        try:
            self.es_client.index(index=INDEX_NAME, body=document)
        except Exception as e:
            print(f"Error indexing document: {e}")
            
    def process_and_index_text(self, text: str, metadata: Dict[str, Any] = None) -> None:
        """process text and index"""
        document = self.process_text(text, metadata)
        self.index_document(document)
        
    def process_and_index_file(self, file_path: str) -> None:
        """process file and index"""
        if not os.path.exists(file_path):
            raise FileNotFoundError(f"File not found: {file_path}")
            
        with open(file_path, 'r', encoding='utf-8') as f:
            content = f.read()
            
        metadata = {
            "source": file_path,
            "filename": os.path.basename(file_path)
        }
        
        self.process_and_index_text(content, metadata) 