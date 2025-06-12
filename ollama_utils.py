import requests
import json
from config import OLLAMA_HOST, MODEL_NAME

class OllamaClient:
    def __init__(self):
        self.base_url = OLLAMA_HOST
        self.model = MODEL_NAME

    def generate_embedding(self, text):
        """generate embedding for text"""
        url = f"{self.base_url}/api/embeddings"
        response = requests.post(url, json={
            "model": self.model,
            "prompt": text
        })
        if response.status_code == 200:
            return response.json()['embedding']
        else:
            raise Exception(f"Error generating embedding: {response.text}")

    def generate_completion(self, prompt, context=None, temperature=0.7):
        """generate text completion"""
        url = f"{self.base_url}/api/generate"
        body = {
            "model": self.model,
            "prompt": prompt,
            "temperature": temperature,
        }
        if context:
            body["context"] = context

        response = requests.post(url, json=body, stream=True)
        
        if response.status_code == 200:
            full_response = ""
            for line in response.iter_lines():
                if line:
                    json_response = json.loads(line)
                    full_response += json_response.get('response', '')
                    if json_response.get('done', False):
                        break
            return full_response
        else:
            raise Exception(f"Error generating completion: {response.text}")

    def chat(self, messages, temperature=0.7):
        """perform chat-style conversation"""
        url = f"{self.base_url}/api/chat"
        response = requests.post(url, json={
            "model": self.model,
            "messages": messages,
            "temperature": temperature,
        }, stream=True)

        if response.status_code == 200:
            full_response = ""
            for line in response.iter_lines():
                if line:
                    json_response = json.loads(line)
                    full_response += json_response.get('message', {}).get('content', '')
                    if json_response.get('done', False):
                        break
            return full_response
        else:
            raise Exception(f"Error in chat: {response.text}") 