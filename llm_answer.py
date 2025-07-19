import pandas as pd
import logging
from langchain_core.prompts import ChatPromptTemplate
from langchain.chains.combine_documents import create_stuff_documents_chain
from langchain.chains import create_retrieval_chain
from langchain_chroma import Chroma
from models import Models

# Setup logging
logging.basicConfig(
    filename="llm_processing.log",
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s",
)

# Initialize the models and vector store
models = Models()
embeddings = models.embeddings_ollama
llm = models.model_ollama

# Initialize the vector store
vector_store = Chroma(
    collection_name="documents",
    embedding_function=embeddings,
    persist_directory="./db/chroma_langchain_db",
)

# Define the chat prompt
prompt = ChatPromptTemplate.from_messages(
    [
        (
            "system",
            "You are a cybersecurity expert assisting with penetration testing (pentesting) questions. "
            "Each question will be followed by multiple-choice options. Your task is to:\n"
            "1. Analyze the question and the provided options using the context provided.\n"
            "2. Select the most appropriate answer from the options.\n"
            "3. Provide a clear and concise explanation for why the selected answer is correct.\n"
            "4. If the context is not sufficient, use your own knowledge to answer.\n"
            "\nContext: {context}"
        ),
        ("human", "Question: {input}\nOptions: {choices}"),
    ]
)

# Define the retrieval chain
retriever = vector_store.as_retriever(kwargs={"k": 5})  # Retrieve top 5 documents
combine_docs_chain = create_stuff_documents_chain(llm, prompt)
retrieval_chain = create_retrieval_chain(retriever, combine_docs_chain)

def generate_llm_answer(question, choices):
    try:
        # Get answer using RAG
        result = retrieval_chain.invoke({"input": question, "choices": choices})
        
        # Determine answer source
        if result["context"]:
            answer_source = "RAG (Knowledge Base)"
            sources = []
            for doc in result["context"]:
                source = doc.metadata.get('source', 'Unknown')
                chunk_id = doc.metadata.get('chunk_id', 'Unknown')
                sources.append(f"{source} (Chunk: {chunk_id})")
        else:
            answer_source = "Model's Base Knowledge"
            sources = ["-"]
        
        # Format the response
        response = {
            "answer": result["answer"].strip(),
            "source": answer_source,
            "sources": "\n".join(sources) if answer_source == "RAG (Knowledge Base)" else "-"
        }
        
        return response
    except Exception as e:
        logging.error(f"Error generating answer for question: {question}. Error: {e}")
        return {
            "answer": f"Error generating answer: {str(e)}",
            "source": "Error",
            "sources": "-"
        }

# Load dataset
df = pd.read_excel("pentesting_dataset_modified.xlsx", engine="openpyxl")

# Prepare new columns
df["LLM_answer"] = None
df["Answer_Source"] = None  # RAG or Model's Knowledge
df["RAG_Sources"] = None    # Details of sources if RAG is used

# Processing parameters
save_interval = 10

for index, row in df.iterrows():
    question = row["question"]
    choices = row["choices"]
    
    if pd.notna(question) and pd.notna(choices):
        print(f"\nProcessing row {index + 1}:")
        print(f"Question: {question}")
        print(f"Options: {choices}")

        # Generate answer
        result = generate_llm_answer(question, choices)
        
        # Store results
        df.at[index, "LLM_answer"] = result["answer"]
        df.at[index, "Answer_Source"] = result["source"]
        df.at[index, "RAG_Sources"] = result["sources"]

        # Display in terminal
        print(f"Answer: {result['answer']}")
        print(f"Source: {result['source']}")
        if result['source'] == "RAG (Knowledge Base)":
            print("Sources used:")
            print(result['sources'])
        print("-" * 50)

        # Log processing
        logging.info(f"Processed row {index + 1}: Question = {question}, Source = {result['source']}")

    # Periodic save
    if (index + 1) % save_interval == 0:
        temp_filename = "dataset_with_llm_answers_temp.xlsx"
        df.to_excel(temp_filename, index=False, engine="openpyxl")
        logging.info(f"Temporarily saved results up to row {index + 1}.")

# Final save
output_filename = "llm_answers_with_source_no_base_dataset.xlsx"
df.to_excel(output_filename, index=False, engine="openpyxl")
logging.info(f"Processing complete. Final results saved to '{output_filename}'.")

# Show sample results
print("\nProcessing complete. Sample results:")
print(df[["question", "Answer_Source", "LLM_answer"]].head())