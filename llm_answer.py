import pandas as pd
import logging
from langchain_core.prompts import ChatPromptTemplate
from langchain.chains.combine_documents import create_stuff_documents_chain
from langchain.chains import create_retrieval_chain
from langchain_chroma import Chroma
from models import AdvancedModels
from advanced_retriever import HybridRetriever

# Setup advanced logging
logging.basicConfig(
    filename="llm_processing_advanced.log",
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s",
)

# Initialize the advanced models and vector store
models = AdvancedModels()
embeddings = models.embeddings_ollama
llm = models.model_ollama

# Initialize the vector store
vector_store = Chroma(
    collection_name="documents",
    embedding_function=embeddings,
    persist_directory="./db/chroma_langchain_db",
)

# Define the advanced chat prompt for cybersecurity
prompt = ChatPromptTemplate.from_messages(
    [
        (
            "system",
            "You are an expert cybersecurity consultant specializing in penetration testing and offensive security. "
            "You have access to comprehensive cybersecurity documentation that has been retrieved using advanced "
            "semantic search and reranking techniques for maximum relevance.\n\n"
            "Your task is to analyze multiple-choice cybersecurity questions and provide expert answers:\n"
            "1. Analyze the question thoroughly using the provided context\n"
            "2. Consider all multiple-choice options carefully\n"
            "3. Select the most technically accurate answer\n"
            "4. Provide a detailed explanation covering:\n"
            "   - Why the selected answer is correct\n"
            "   - Why other options are incorrect or less optimal\n"
            "   - Relevant tools, techniques, or commands\n"
            "   - Real-world application scenarios\n"
            "5. Reference specific information from the context when available\n"
            "6. Apply your cybersecurity expertise to supplement the context\n\n"
            "Context from Advanced RAG Retrieval:\n{context}"
        ),
        ("human", "Cybersecurity Question: {input}\n\nMultiple Choice Options: {choices}\n\nPlease provide your expert analysis and answer."),
    ]
)

# Initialize Advanced Hybrid Retriever
retriever = HybridRetriever(
    vector_store=vector_store,
    models=models,
    dense_k=20,              # More documents for comprehensive analysis
    sparse_k=15,             # Additional keyword-based results
    final_k=10,              # Top 10 most relevant after reranking
    dense_weight=0.75,       # Higher weight for semantic similarity
    sparse_weight=0.25,      # Lower weight for keyword matching
    enable_reranking=True,   # Enable cross-encoder reranking
    enable_query_enhancement=True  # Enable query expansion
)

# Create advanced retrieval chain
combine_docs_chain = create_stuff_documents_chain(llm, prompt)
retrieval_chain = create_retrieval_chain(retriever, combine_docs_chain)

def generate_advanced_llm_answer(question, choices):
    """
    Generate answer using Advanced RAG with enhanced analysis.
    """
    try:
        print(f"🔍 Processing with Advanced RAG...")
        
        # Get answer using Advanced RAG
        result = retrieval_chain.invoke({"input": question, "choices": choices})
        
        # Enhanced source analysis
        if result["context"]:
            answer_source = "Advanced RAG (Hybrid + Reranked)"
            sources = []
            retrieval_types = []
            
            for doc in result["context"]:
                source = doc.metadata.get('source', 'Unknown')
                chunk_id = doc.metadata.get('chunk_id', 'Unknown')
                retrieval_type = doc.metadata.get('retrieval_type', 'semantic')
                rank = doc.metadata.get('retrieval_rank', 'N/A')
                
                sources.append(f"{source} (Chunk: {chunk_id}, Type: {retrieval_type}, Rank: {rank})")
                retrieval_types.append(retrieval_type)
            
            # Calculate retrieval statistics
            semantic_count = retrieval_types.count('dense')
            keyword_count = retrieval_types.count('sparse')
            
            retrieval_stats = f"Semantic: {semantic_count}, Keyword: {keyword_count}, Total: {len(result['context'])}"
            
        else:
            answer_source = "Model's Base Knowledge"
            sources = ["-"]
            retrieval_stats = "No relevant documents found"
        
        # Enhanced response format
        response = {
            "answer": result["answer"].strip(),
            "source": answer_source,
            "sources": "\n".join(sources) if answer_source.startswith("Advanced RAG") else "-",
            "retrieval_stats": retrieval_stats,
            "context_length": len(result.get("context", [])),
            "enhanced_features": "Hybrid Search + Reranking + Query Enhancement"
        }
        
        return response
        
    except Exception as e:
        error_msg = f"Error in Advanced RAG: {str(e)}"
        logging.error(f"Error generating answer for question: {question}. Error: {e}")
        
        # Fallback to basic retrieval
        try:
            print("⚠️  Falling back to basic retrieval...")
            basic_retriever = vector_store.as_retriever(search_kwargs={"k": 5})
            basic_chain = create_retrieval_chain(basic_retriever, combine_docs_chain)
            fallback_result = basic_chain.invoke({"input": question, "choices": choices})
            
            return {
                "answer": fallback_result["answer"].strip(),
                "source": "Basic RAG (Fallback)",
                "sources": "Fallback mode - limited source tracking",
                "retrieval_stats": "Fallback: Basic semantic search",
                "context_length": len(fallback_result.get("context", [])),
                "enhanced_features": "Fallback mode"
            }
            
        except Exception as e2:
            return {
                "answer": f"Error: {error_msg}. Fallback also failed: {str(e2)}",
                "source": "Error",
                "sources": "-",
                "retrieval_stats": "Failed",
                "context_length": 0,
                "enhanced_features": "Failed"
            }

# Load dataset
df = pd.read_excel("pentesting_dataset_modified.xlsx", engine="openpyxl")

# Prepare enhanced columns for Advanced RAG
df["LLM_answer"] = None
df["Answer_Source"] = None  
df["RAG_Sources"] = None    
df["Retrieval_Stats"] = None      # New: Statistics about retrieval
df["Context_Length"] = None       # New: Number of context documents
df["Enhanced_Features"] = None    # New: Features used

# Processing parameters
save_interval = 10

print("🚀 Starting Advanced RAG Processing...")
print(f"📊 Dataset size: {len(df)} questions")
print(f"🔧 Features: Hybrid Retrieval + Reranking + Query Enhancement")
print("-" * 60)

for index, row in df.iterrows():
    question = row["question"]
    choices = row["choices"]
    
    if pd.notna(question) and pd.notna(choices):
        print(f"\n📋 Processing row {index + 1}/{len(df)}:")
        print(f"❓ Question: {question[:100]}...")
        print(f"📝 Options: {str(choices)[:100]}...")

        # Generate answer using Advanced RAG
        result = generate_advanced_llm_answer(question, choices)
        
        # Store enhanced results
        df.at[index, "LLM_answer"] = result["answer"]
        df.at[index, "Answer_Source"] = result["source"]
        df.at[index, "RAG_Sources"] = result["sources"]
        df.at[index, "Retrieval_Stats"] = result["retrieval_stats"]
        df.at[index, "Context_Length"] = result["context_length"]
        df.at[index, "Enhanced_Features"] = result["enhanced_features"]

        # Enhanced terminal display
        print(f"✅ Answer: {result['answer'][:150]}...")
        print(f"🎯 Source: {result['source']}")
        print(f"📊 Retrieval: {result['retrieval_stats']}")
        print(f"📄 Contexts: {result['context_length']}")
        
        if result['source'].startswith("Advanced RAG"):
            print(f"🔍 Enhanced Features: {result['enhanced_features']}")
            print("📚 Sources:")
            for i, source in enumerate(result['sources'].split('\n')[:3]):
                if source.strip() and source != "-":
                    print(f"   {i+1}. {source[:80]}...")
        
        print("🔄 " + "-" * 50)

        # Log processing with enhanced info
        logging.info(f"Processed row {index + 1}: Question = {question[:50]}..., "
                    f"Source = {result['source']}, Context = {result['context_length']}")

    # Periodic save with enhanced filename
    if (index + 1) % save_interval == 0:
        temp_filename = "dataset_advanced_rag_temp.xlsx"
        df.to_excel(temp_filename, index=False, engine="openpyxl")
        logging.info(f"Temporarily saved Advanced RAG results up to row {index + 1}.")
        print(f"💾 Auto-saved progress: {index + 1}/{len(df)} completed")

# Final save with enhanced results
output_filename = "advanced_rag_results.xlsx"
df.to_excel(output_filename, index=False, engine="openpyxl")
logging.info(f"Advanced RAG processing complete. Final results saved to '{output_filename}'.")

# Enhanced results summary
print("\n" + "="*60)
print("🎉 ADVANCED RAG PROCESSING COMPLETE!")
print("="*60)

# Statistics
source_counts = df["Answer_Source"].value_counts()
avg_context_length = df["Context_Length"].mean()

print(f"📊 Processing Statistics:")
print(f"   📋 Total Questions: {len(df)}")
print(f"   📄 Average Context Docs: {avg_context_length:.2f}")
print(f"   📚 Source Distribution:")
for source, count in source_counts.items():
    print(f"      - {source}: {count} questions ({count/len(df)*100:.1f}%)")

print(f"\n💾 Results saved to: {output_filename}")
print(f"📝 Processing log: llm_processing_advanced.log")

# Show enhanced sample results
print(f"\n📋 Sample Results:")
print(df[["question", "Answer_Source", "Retrieval_Stats", "Context_Length"]].head())