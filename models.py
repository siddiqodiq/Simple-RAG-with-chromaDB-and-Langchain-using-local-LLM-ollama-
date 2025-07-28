import os
import warnings
from langchain_ollama import OllamaEmbeddings, ChatOllama
from langchain_huggingface import HuggingFaceEmbeddings
from langchain.retrievers.document_compressors import LLMChainExtractor
from langchain.retrievers import ContextualCompressionRetriever
from sentence_transformers import CrossEncoder
import numpy as np
from typing import List, Dict, Any

# Suppress future warnings from transformers
warnings.filterwarnings("ignore", category=FutureWarning, module="torch.nn.modules.module")

class AdvancedModels:
    def __init__(self):
        """Inisialisasi advanced models dengan berbagai opsi embedding dan reranking."""

        # IP WSL (ganti sesuai IP yang ditemukan di langkah 1)
        ollama_host = "http://127.0.0.1:11434"

        # Primary embedding model (Ollama) - optimized configuration
        self.embeddings_ollama = OllamaEmbeddings(
            model="nomic-embed-text", 
            base_url=ollama_host,
        )
        
        # Secondary embedding model untuk hybrid retrieval
        self.embeddings_huggingface = HuggingFaceEmbeddings(
            model_name="all-MiniLM-L6-v2",
            model_kwargs={'device': 'cpu'},
            encode_kwargs={'normalize_embeddings': True}
        )

        # Main LLM model - cleaned configuration
        self.model_ollama = ChatOllama(
            model="pentest-ai", 
            temperature=0, 
            base_url=ollama_host,
            # Explicit parameters to avoid warnings
            num_predict=512,  # Limit response length
            top_k=40,        # Standard sampling parameter
            top_p=0.9,       # Standard sampling parameter
        )

        # Cross-encoder untuk reranking dengan model yang lebih stabil
        try:
            self.reranker = CrossEncoder('cross-encoder/ms-marco-MiniLM-L-6-v2')
        except Exception as e:
            print(f"Warning: Could not load cross-encoder model: {e}")
            print("Using fallback similarity scoring...")
            self.reranker = None
        
        # Context compressor untuk advanced filtering
        self.compressor = LLMChainExtractor.from_llm(self.model_ollama)

    def embed_query_safe(self, query: str) -> List[float]:
        """
        Safe embedding method to avoid batch decoding issues.
        """
        try:
            # Use single query embedding to avoid batch issues
            return self.embeddings_ollama.embed_query(query)
        except Exception as e:
            print(f"Warning: Ollama embedding failed: {e}")
            print("Falling back to HuggingFace embeddings...")
            try:
                return self.embeddings_huggingface.embed_query(query)
            except Exception as e2:
                print(f"Error: Both embedding methods failed: {e2}")
                return []

    def embed_documents_safe(self, documents: List[str]) -> List[List[float]]:
        """
        Safe document embedding method with error handling.
        """
        try:
            # Process in smaller batches to avoid decode issues
            batch_size = 5
            all_embeddings = []
            
            for i in range(0, len(documents), batch_size):
                batch = documents[i:i + batch_size]
                try:
                    batch_embeddings = self.embeddings_ollama.embed_documents(batch)
                    all_embeddings.extend(batch_embeddings)
                except Exception as e:
                    print(f"Warning: Batch {i//batch_size + 1} failed with Ollama: {e}")
                    # Fallback to individual processing
                    for doc in batch:
                        try:
                            embedding = self.embeddings_ollama.embed_query(doc)
                            all_embeddings.append(embedding)
                        except:
                            # Final fallback to HuggingFace
                            try:
                                embedding = self.embeddings_huggingface.embed_query(doc)
                                all_embeddings.append(embedding)
                            except:
                                print(f"Error: Failed to embed document: {doc[:50]}...")
                                all_embeddings.append([])
            
            return all_embeddings
        except Exception as e:
            print(f"Error in embed_documents_safe: {e}")
            return []

    def rerank_documents(self, query: str, documents: List[Any], top_k: int = 5) -> List[Any]:
        """
        Rerank documents menggunakan cross-encoder model.
        """
        if not documents:
            return documents
        
        if self.reranker is None:
            # Fallback: use simple text similarity
            print("Using fallback similarity scoring for reranking...")
            # Simple fallback based on query term frequency
            query_terms = set(query.lower().split())
            
            scored_docs = []
            for doc in documents:
                doc_terms = set(doc.page_content.lower().split())
                # Simple Jaccard similarity
                intersection = len(query_terms.intersection(doc_terms))
                union = len(query_terms.union(doc_terms))
                score = intersection / union if union > 0 else 0
                scored_docs.append((doc, score))
            
            # Sort by score
            scored_docs.sort(key=lambda x: x[1], reverse=True)
            return [doc for doc, score in scored_docs[:top_k]]
        
        try:
            # Suppress warnings during prediction
            with warnings.catch_warnings():
                warnings.simplefilter("ignore")
                
                # Prepare pairs untuk reranking
                pairs = [(query, doc.page_content) for doc in documents]
                
                # Get reranking scores
                scores = self.reranker.predict(pairs)
                
                # Sort documents berdasarkan score
                doc_scores = list(zip(documents, scores))
                doc_scores.sort(key=lambda x: x[1], reverse=True)
                
                # Return top-k documents
                return [doc for doc, score in doc_scores[:top_k]]
                
        except Exception as e:
            print(f"Warning: Reranking failed: {e}")
            print("Falling back to original document order...")
            return documents[:top_k]

    def enhance_query(self, query: str) -> List[str]:
        """
        Generate multiple query variations untuk improved retrieval.
        """
        enhanced_queries = [query]  # Original query
        
        # Add query expansions
        # Simple keyword expansion untuk cybersecurity terms
        cybersec_synonyms = {
            'hack': ['exploit', 'penetrate', 'compromise'],
            'vulnerability': ['weakness', 'flaw', 'security hole'],
            'malware': ['virus', 'trojan', 'malicious software'],
            'attack': ['assault', 'offensive', 'breach'],
            'penetration testing': ['pentest', 'security testing', 'ethical hacking']
        }
        
        # Add expanded queries
        for term, synonyms in cybersec_synonyms.items():
            if term.lower() in query.lower():
                for synonym in synonyms:
                    enhanced_query = query.replace(term, synonym)
                    enhanced_queries.append(enhanced_query)
                    
        return enhanced_queries[:3]  # Return top 3 variations

    def invoke_llm_safe(self, prompt: str, max_retries: int = 3) -> str:
        """
        Safe LLM invocation with retry logic and error handling.
        """
        for attempt in range(max_retries):
            try:
                response = self.model_ollama.invoke(prompt)
                if hasattr(response, 'content'):
                    return response.content
                else:
                    return str(response)
            except Exception as e:
                print(f"Warning: LLM invocation attempt {attempt + 1} failed: {e}")
                if attempt == max_retries - 1:
                    return f"Error: Unable to get response from LLM after {max_retries} attempts. Last error: {e}"
                else:
                    import time
                    time.sleep(1)  # Wait before retry
        
        return "Error: Unable to get response from LLM"

# Backward compatibility
class Models(AdvancedModels):
    """Backward compatibility class."""
    pass

# Contoh penggunaan
local_model = AdvancedModels()
