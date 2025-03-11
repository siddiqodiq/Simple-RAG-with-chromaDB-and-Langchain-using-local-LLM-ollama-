from langchain_core.prompts import ChatPromptTemplate
from langchain.chains.combine_documents import create_stuff_documents_chain
from langchain.chains import create_retrieval_chain
from langchain_chroma import Chroma
from models import Models

# Initialize the models
models = Models()
embeddings = models.embeddings_ollama
llm = models.model_ollama

# Initialize the vector store
vector_store = Chroma(
    collection_name="documents",
    embedding_function=embeddings,
    persist_directory="./db/chroma_langchain_db",  # Where to save data locally
)

# Define the chat prompt
prompt = ChatPromptTemplate.from_messages(
    [
        (
            "system",
            "You are an assistant. Your task is to answer questions based on the provided documents. "
            "If the data is insufficient, you can supplement your answer with your own knowledge. "
            "However, prioritize the provided data for accuracy."
        ),
        ("human", "Question: {input}\n\nContext: {context}"),
    ]
)

# Define the retrieval chain
retriever = vector_store.as_retriever(kwargs={"k": 10})  # Retrieve top 10 documents
combine_docs_chain = create_stuff_documents_chain(llm, prompt)
retrieval_chain = create_retrieval_chain(retriever, combine_docs_chain)

# Main loop
def main():
    while True:
        query = input("User (or type 'q', 'quit', or 'exit' to end): ")
        if query.lower() in ['q', 'quit', 'exit']:
            break

        result = retrieval_chain.invoke({"input": query})
        
        # Check if RAG is used
        if result["context"]:
            print("\nAssistant is using Knowledge RAG to answer the question.")
            # Display the source documents or chunks used
            print("\nSources used for the answer:")
            for i, doc in enumerate(result["context"]):
                print(f"Source {i+1}:")
                print(f"Document: {doc.metadata.get('source', 'Unknown')}")
                print(f"Chunk: {doc.metadata.get('chunk_id', 'Unknown')}")
                print(f"Content: {doc.page_content[:200]}...")  # Display first 200 characters of the chunk
                print("-" * 50)
        else:
            print("\nAssistant is answering based on its own knowledge (no RAG).")
        
        # Display the answer
        print("\nAssistant: ", result["answer"], "\n\n")

# Run the main loop
if __name__ == "__main__":
    main()