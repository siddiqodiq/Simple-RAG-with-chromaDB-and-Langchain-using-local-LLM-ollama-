# RAG with LangChain and Ollama

This project is an implementation of **Retrieval-Augmented Generation (RAG)** using **LangChain**, **ChromaDB**, and **Ollama** to enhance answer accuracy in an LLM-based (Large Language Model) system. The system performs document-based retrieval and answers user questions using data stored in the vector database.

## Features
- **Integration with Ollama** as the LLM model.
- **ChromaDB** as a vector storage for documents.
- **RAG pipeline** for document retrieval and processing.
- **PDF ingestion support** to add documents to the vector database.
- **Interactive system** for answering user queries.

## Installation
### 1. Requirements
Ensure Python is installed (recommended version 3.8+).

### 2. Clone the Repository
```bash
git clone https://github.com/username/rag-langchain-ollama.git
cd rag-langchain-ollama
```

### 3. Install Dependencies
```bash
pip install -r requirements.txt
```

### 4. Run Ollama
Ensure the **Ollama** server is running locally (example with WSL):
```bash
ollama serve
```
You can change model by modified code at models.py
```python
# Model LLM Ollama
        self.model_ollama = ChatOllama(model="put your model LLM here", temperature=0, base_url=ollama_host)
```

## Usage
### 1. Run the Ingestor to Add Documents
```bash
python ingest.py
```
PDF files in the `data/` folder will be processed and stored in **ChromaDB**.

### 2. Run the Interactive Chatbot
```bash
python main.py
```
Use this chatbot to ask questions based on indexed documents.

## Project Structure
```
├── data/                  # Folder for PDF documents
├── db/                    # ChromaDB storage folder
├── models.py              # Ollama model used (can be customized)
├── ingest.py              # Script for processing documents
├── chat.py                # Interactive chatbot
├── requirements.txt       # List of dependencies
└── README.md              # Project documentation
```

## Documentation
![image](https://github.com/user-attachments/assets/3f21b3fe-cbb0-4ebc-873e-4ee30ed2290f)

