import os
from langchain_ollama import OllamaEmbeddings, ChatOllama

class Models:
    def __init__(self):
        """Inisialisasi model lokal dengan Ollama."""

        # IP WSL (ganti sesuai IP yang ditemukan di langkah 1)
        ollama_host = "http://127.0.0.1:11434"

        # Model embedding Ollama
        self.embeddings_ollama = OllamaEmbeddings(model="nomic-embed-text", base_url=ollama_host)

        # Model LLM Ollama
        self.model_ollama = ChatOllama(model="pentest-ai", temperature=0, base_url=ollama_host)

# Contoh penggunaan
local_model = Models()
