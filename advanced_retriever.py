import numpy as np
from typing import List, Dict, Any, Optional
from langchain_core.documents import Document
from langchain_core.retrievers import BaseRetriever
from langchain_core.callbacks import CallbackManagerForRetrieverRun
from langchain_chroma import Chroma
from rank_bm25 import BM25Okapi
from models import AdvancedModels
from pydantic import Field

class HybridRetriever(BaseRetriever):
    """
    Hybrid Retriever yang menggabungkan:
    1. Dense retrieval (semantic search)
    2. Sparse retrieval (BM25/keyword search)
    3. Reranking dengan cross-encoder
    """
    
    # Define Pydantic fields for compatibility
    vector_store: Chroma = Field(description="ChromaDB vector store")
    models: AdvancedModels = Field(description="Advanced models instance")
    dense_k: int = Field(default=20, description="Number of documents for dense retrieval")
    sparse_k: int = Field(default=20, description="Number of documents for sparse retrieval")
    final_k: int = Field(default=10, description="Final number of documents to return")
    dense_weight: float = Field(default=0.7, description="Weight for dense retrieval")
    sparse_weight: float = Field(default=0.3, description="Weight for sparse retrieval")
    enable_reranking: bool = Field(default=True, description="Enable cross-encoder reranking")
    
    # Private fields for BM25
    bm25: Optional[BM25Okapi] = Field(default=None, exclude=True)
    bm25_docs: List[str] = Field(default_factory=list, exclude=True)
    bm25_metadatas: List[Dict] = Field(default_factory=list, exclude=True)
    
    class Config:
        arbitrary_types_allowed = True
    
    def __init__(
        self,
        vector_store: Chroma,
        models: AdvancedModels,
        dense_k: int = 20,
        sparse_k: int = 20,
        final_k: int = 5,
        dense_weight: float = 0.7,
        sparse_weight: float = 0.3,
        enable_reranking: bool = True,
        **kwargs
    ):
        super().__init__(
            vector_store=vector_store,
            models=models,
            dense_k=dense_k,
            sparse_k=sparse_k,
            final_k=final_k,
            dense_weight=dense_weight,
            sparse_weight=sparse_weight,
            enable_reranking=enable_reranking,
            **kwargs
        )
        
        # Initialize BM25 for sparse retrieval
        self._initialize_bm25()
        
    def _initialize_bm25(self):
        """Initialize BM25 index dari dokumen yang ada di ChromaDB."""
        try:
            # Get all documents from ChromaDB
            all_docs = self.vector_store.get()
            
            if all_docs and 'documents' in all_docs:
                # Tokenize documents untuk BM25
                tokenized_docs = [doc.split() for doc in all_docs['documents']]
                self.bm25 = BM25Okapi(tokenized_docs)
                self.bm25_docs = all_docs['documents']
                self.bm25_metadatas = all_docs.get('metadatas', [])
                print(f"BM25 initialized with {len(tokenized_docs)} documents")
            else:
                self.bm25 = None
                self.bm25_docs = []
                self.bm25_metadatas = []
                print("No documents found for BM25 initialization")
                
        except Exception as e:
            print(f"Error initializing BM25: {e}")
            self.bm25 = None
            self.bm25_docs = []
            self.bm25_metadatas = []

    def _dense_retrieval(self, query: str, k: int) -> List[Document]:
        """Dense retrieval menggunakan semantic search."""
        try:
            retriever = self.vector_store.as_retriever(search_kwargs={"k": k})
            docs = retriever.invoke(query)
            return docs
        except Exception as e:
            print(f"Error in dense retrieval: {e}")
            return []

    def _sparse_retrieval(self, query: str, k: int) -> List[Document]:
        """Sparse retrieval menggunakan BM25."""
        if not self.bm25 or not self.bm25_docs:
            return []
            
        try:
            # Tokenize query
            tokenized_query = query.split()
            
            # Get BM25 scores
            scores = self.bm25.get_scores(tokenized_query)
            
            # Get top-k indices
            top_indices = np.argsort(scores)[::-1][:k]
            
            # Convert ke Document objects
            docs = []
            for idx in top_indices:
                if idx < len(self.bm25_docs) and scores[idx] > 0:
                    metadata = self.bm25_metadatas[idx] if idx < len(self.bm25_metadatas) else {}
                    doc = Document(
                        page_content=self.bm25_docs[idx],
                        metadata=metadata
                    )
                    docs.append(doc)
                    
            return docs
            
        except Exception as e:
            print(f"Error in sparse retrieval: {e}")
            return []

    def _merge_and_deduplicate(self, dense_docs: List[Document], sparse_docs: List[Document]) -> List[Document]:
        """Merge dan deduplicate documents dari dense dan sparse retrieval."""
        seen_content = set()
        merged_docs = []
        
        # Add dense docs dengan weight lebih tinggi
        for doc in dense_docs:
            content_hash = hash(doc.page_content[:100])  # Hash first 100 chars
            if content_hash not in seen_content:
                doc.metadata['retrieval_type'] = 'dense'
                doc.metadata['score'] = self.dense_weight
                merged_docs.append(doc)
                seen_content.add(content_hash)
        
        # Add sparse docs
        for doc in sparse_docs:
            content_hash = hash(doc.page_content[:100])
            if content_hash not in seen_content:
                doc.metadata['retrieval_type'] = 'sparse'
                doc.metadata['score'] = self.sparse_weight
                merged_docs.append(doc)
                seen_content.add(content_hash)
        
        return merged_docs

    def _get_relevant_documents(
        self, 
        query: str, 
        *, 
        run_manager: CallbackManagerForRetrieverRun
    ) -> List[Document]:
        """Main retrieval method."""
        
        # Dense retrieval
        dense_docs = self._dense_retrieval(query, self.dense_k)
        
        # Sparse retrieval
        sparse_docs = self._sparse_retrieval(query, self.sparse_k)
        
        # Merge results
        final_docs = self._merge_and_deduplicate(dense_docs, sparse_docs)
        
        # Reranking
        if self.enable_reranking and final_docs:
            try:
                final_docs = self.models.rerank_documents(query, final_docs, self.final_k)
            except Exception as e:
                print(f"Error in reranking: {e}")
                final_docs = final_docs[:self.final_k]
        else:
            final_docs = final_docs[:self.final_k]
        
        # Add retrieval metadata
        for i, doc in enumerate(final_docs):
            doc.metadata['retrieval_rank'] = i + 1
            doc.metadata['retrieval_method'] = 'hybrid'
            
        return final_docs

class MultiQueryRetriever(BaseRetriever):
    """
    Multi-Query Retriever yang menggunakan LLM untuk generate 
    multiple query variations.
    """
    
    # Define Pydantic fields
    base_retriever: BaseRetriever = Field(description="Base retriever to use")
    models: AdvancedModels = Field(description="Advanced models instance")
    num_queries: int = Field(default=3, description="Number of query variations to generate")
    
    class Config:
        arbitrary_types_allowed = True
    
    def __init__(
        self,
        base_retriever: BaseRetriever,
        models: AdvancedModels,
        num_queries: int = 3,
        **kwargs
    ):
        super().__init__(
            base_retriever=base_retriever,
            models=models,
            num_queries=num_queries,
            **kwargs
        )
    
    def _generate_queries(self, original_query: str) -> List[str]:
        """Generate multiple query variations using LLM."""
        try:
            prompt = f"""
            You are an expert in cybersecurity and penetration testing. 
            Given the original question, generate {self.num_queries - 1} alternative ways to ask the same question that might help retrieve relevant cybersecurity documents.
            
            Original question: {original_query}
            
            Alternative questions (one per line):
            """
            
            response = self.models.model_ollama.invoke(prompt)
            
            # Parse response
            lines = response.content.strip().split('\n')
            alternative_queries = [line.strip() for line in lines if line.strip()]
            
            # Return original + alternatives
            all_queries = [original_query] + alternative_queries[:self.num_queries-1]
            return all_queries
            
        except Exception as e:
            print(f"Error generating queries: {e}")
            return [original_query]
    
    def _get_relevant_documents(
        self, 
        query: str, 
        *, 
        run_manager: CallbackManagerForRetrieverRun
    ) -> List[Document]:
        """Retrieve documents using multiple query variations."""
        
        # Generate query variations
        queries = self._generate_queries(query)
        
        all_docs = []
        seen_content = set()
        
        # Retrieve for each query
        for q in queries:
            try:
                docs = self.base_retriever.invoke(q)
                
                # Deduplicate
                for doc in docs:
                    content_hash = hash(doc.page_content[:100])
                    if content_hash not in seen_content:
                        doc.metadata['source_query'] = q
                        all_docs.append(doc)
                        seen_content.add(content_hash)
                        
            except Exception as e:
                print(f"Error retrieving for query '{q}': {e}")
        
        return all_docs[:10]  # Return top 10
