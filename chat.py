import warnings
warnings.filterwarnings("ignore", category=FutureWarning, module="torch.nn.modules.module")

from langchain_core.prompts import ChatPromptTemplate
from langchain.chains.combine_documents import create_stuff_documents_chain
from langchain.chains import create_retrieval_chain
from langchain_chroma import Chroma
from models import AdvancedModels
from advanced_retriever import HybridRetriever

# Initialize the advanced models
models = AdvancedModels()
embeddings = models.embeddings_ollama
llm = models.model_ollama

# Initialize the vector store
vector_store = Chroma(
    collection_name="documents",
    embedding_function=embeddings,
    persist_directory="./db/chroma_langchain_db",  # Where to save data locally
)

# Define the advanced chat prompt
prompt = ChatPromptTemplate.from_messages(
    [
        (
            "system",
            "You are an expert cybersecurity assistant specializing in penetration testing and offensive security. "
            "Your task is to provide comprehensive and accurate answers based on the provided documents. "
            "The documents have been retrieved using hybrid search with semantic and keyword techniques, "
            "and have been reranked for relevance to the user's question.\n\n"
            "Guidelines:\n"
            "1. Prioritize information from the provided context documents\n"
            "2. If the context is insufficient, supplement with your cybersecurity expertise\n"
            "3. Provide practical, actionable information\n"
            "4. Include relevant commands, tools, or techniques when applicable\n"
            "5. Mention the sources of your information when possible\n\n"
            "Context: {context}"
        ),
        ("human", "Question: {input}"),
    ]
)

# Initialize Retrieval System
def get_retriever(retrieval_mode="hybrid"):
    """
    Get retriever based on mode.
    Modes: 'hybrid', 'naive'
    """
    if retrieval_mode == "hybrid":
        # Hybrid Retriever (Dense + Sparse + Reranking)
        return HybridRetriever(
            vector_store=vector_store,
            models=models,
            dense_k=15,           # Retrieve 15 docs via semantic search
            sparse_k=10,          # Retrieve 10 docs via BM25
            final_k=8,            # Final top 8 after reranking
            dense_weight=0.7,     # 70% weight for semantic search
            sparse_weight=0.3,    # 30% weight for keyword search
            enable_reranking=True
        )
    
    else:  # naive
        # Original naive retriever
        return vector_store.as_retriever(search_kwargs={"k": 10})

# Select retrieval mode
RETRIEVAL_MODE = "hybrid"  # Options: 'hybrid', 'naive'
retriever = get_retriever(RETRIEVAL_MODE)

# Create retrieval chain
combine_docs_chain = create_stuff_documents_chain(llm, prompt)
retrieval_chain = create_retrieval_chain(retriever, combine_docs_chain)

# Main loop with advanced features
def main():
    print(f"🚀 RAG Chat System Initialized!")
    print(f"📊 Retrieval Mode: {RETRIEVAL_MODE.upper()}")
    print(f"🔧 Features: Hybrid Search + Reranking")
    print(f"📚 Database: ChromaDB with {vector_store._collection.count()} documents")
    print("-" * 60)
    
    while True:
        query = input("\n🔍 User (or type 'q', 'quit', or 'exit' to end): ")
        if query.lower() in ['q', 'quit', 'exit']:
            break

        try:
            print("⏳ Processing with RAG...")
            result = retrieval_chain.invoke({"input": query})

            # Enhanced result display
            if result["context"]:
                print(f"\n✅ Assistant is using RAG (Mode: {RETRIEVAL_MODE.upper()})")
                print(f"📄 Retrieved {len(result['context'])} relevant documents:")
                print("\n" + "="*50 + " SOURCES " + "="*50)
                for i, doc in enumerate(result["context"]):
                    print(f"\n📖 Source {i+1}:")
                    print(f"   📁 Document: {doc.metadata.get('source', 'Unknown')}")
                    print(f"   🆔 Chunk ID: {doc.metadata.get('chunk_id', 'Unknown')}")
                    if 'retrieval_type' in doc.metadata:
                        print(f"   🔍 Retrieval: {doc.metadata.get('retrieval_type', 'unknown')}")
                    if 'retrieval_rank' in doc.metadata:
                        print(f"   🏆 Rank: {doc.metadata.get('retrieval_rank', 'unknown')}")
                    print(f"   📝 Content: {doc.page_content[:200]}...")
                    print("   " + "-"*80)
            else:
                print("\n⚠️  No relevant documents found. Using base model knowledge.")

            print("\n" + "="*50 + " ANSWER " + "="*50)
            
            # --- STREAMING OUTPUT ---
            if hasattr(llm, "stream"):
                # Gunakan streaming jika LLM mendukung
                print("🤖 Assistant: ", end="", flush=True)
                stream = llm.stream(result["answer"])
                for chunk in stream:
                    print(chunk, end="", flush=True)
                print()
            else:
                # Fallback: tampilkan sekaligus
                print(f"🤖 Assistant: {result['answer']}")
            print("="*108)
            
        except Exception as e:
            print(f"❌ Error: {e}")
            print("🔄 Falling back to basic retrieval...")
            try:
                basic_retriever = vector_store.as_retriever(search_kwargs={"k": 5})
                basic_chain = create_retrieval_chain(basic_retriever, combine_docs_chain)
                result = basic_chain.invoke({"input": query})
                print(f"🤖 Assistant (Basic): {result['answer']}")
            except Exception as e2:
                print(f"❌ Fallback also failed: {e2}")

# Run the main loop
if __name__ == "__main__":
    main()