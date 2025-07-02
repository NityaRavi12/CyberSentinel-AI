"""
RAG Pipeline for CyberSentinel AI - ATITA
Uses LeetTools + nomic-embed-text + FAISS for local vector database
"""

import asyncio
import os
import json
from typing import Dict, Any, List, Optional
from pathlib import Path
import faiss
import numpy as np
from nomic import embed
from core.config import settings
from core.logging import get_logger

logger = get_logger("rag_pipeline")

class RAGPipeline:
    """RAG pipeline using LeetTools, nomic-embed-text, and FAISS"""
    
    def __init__(self):
        self.knowledge_base_path = Path(settings.rag_knowledge_base_path)
        self.knowledge_base_path.mkdir(parents=True, exist_ok=True)
        self.index_path = self.knowledge_base_path / "faiss_index"
        self.metadata_path = self.knowledge_base_path / "metadata.json"
        self.index = None
        self.metadata = []
        self.embedding_model = None
        self._initialize_embedding_model()
        self._load_index()
    
    def _initialize_embedding_model(self):
        """Initialize nomic embedding model"""
        try:
            # Use nomic-embed-text model
            self.embedding_model = embed.text
            logger.info("Nomic embedding model initialized")
        except Exception as e:
            logger.error(f"Failed to initialize embedding model: {e}")
            self.embedding_model = None
    
    def _load_index(self):
        """Load existing FAISS index and metadata"""
        try:
            if self.index_path.exists() and self.metadata_path.exists():
                self.index = faiss.read_index(str(self.index_path))
                with open(self.metadata_path, 'r') as f:
                    self.metadata = json.load(f)
                logger.info(f"Loaded existing index with {len(self.metadata)} documents")
            else:
                # Create new index
                self.index = faiss.IndexFlatIP(768)  # nomic-embed-text-v1.5 dimension
                self.metadata = []
                logger.info("Created new FAISS index")
        except Exception as e:
            logger.error(f"Failed to load index: {e}")
            self.index = faiss.IndexFlatIP(768)
            self.metadata = []
    
    def _save_index(self):
        """Save FAISS index and metadata"""
        try:
            faiss.write_index(self.index, str(self.index_path))
            with open(self.metadata_path, 'w') as f:
                json.dump(self.metadata, f, indent=2)
            logger.info("Index saved successfully")
        except Exception as e:
            logger.error(f"Failed to save index: {e}")
    
    async def add_documents(self, documents: List[Dict[str, Any]]):
        """Add documents to the knowledge base"""
        if not self.embedding_model or not self.index:
            logger.error("Embedding model or index not available")
            return
        
        try:
            # Extract text content
            texts = []
            for doc in documents:
                text = f"{doc.get('title', '')} {doc.get('content', '')} {doc.get('description', '')}"
                texts.append(text)
            
            # Generate embeddings
            embedding_result = self.embedding_model(texts)
            embeddings = np.array(embedding_result['embeddings'])
            
            # Add to FAISS index
            self.index.add(embeddings.astype('float32'))  # type: ignore
            
            # Store metadata
            for i, doc in enumerate(documents):
                doc_metadata = {
                    "id": doc.get("id", f"doc_{len(self.metadata)}"),
                    "title": doc.get("title", ""),
                    "content": doc.get("content", ""),
                    "source": doc.get("source", ""),
                    "timestamp": doc.get("timestamp", ""),
                    "tags": doc.get("tags", []),
                    "index": len(self.metadata)
                }
                self.metadata.append(doc_metadata)
            
            # Save index
            self._save_index()
            logger.info(f"Added {len(documents)} documents to knowledge base")
            
        except Exception as e:
            logger.error(f"Failed to add documents: {e}")
    
    async def search(self, query: str, top_k: int = 5) -> List[Dict[str, Any]]:
        """Search knowledge base for relevant documents"""
        if not self.embedding_model or not self.index:
            logger.error("Embedding model or index not available")
            return []
        
        try:
            # Generate query embedding
            query_result = self.embedding_model([query])
            query_embedding = np.array(query_result['embeddings'])
            
            # Search FAISS index
            scores, indices = self.index.search(  # type: ignore
                query_embedding.astype('float32'), 
                min(top_k, len(self.metadata))
            )
            
            # Retrieve results
            results = []
            for score, idx in zip(scores[0], indices[0]):
                if idx < len(self.metadata):
                    result = {
                        **self.metadata[idx],
                        "score": float(score)
                    }
                    results.append(result)
            
            logger.info(f"Search returned {len(results)} results")
            return results
            
        except Exception as e:
            logger.error(f"Search failed: {e}")
            return []
    
    async def add_threat_intelligence(self, threat_data: Dict[str, Any]):
        """Add threat intelligence data to knowledge base"""
        document = {
            "id": f"threat_{threat_data.get('id', 'unknown')}",
            "title": threat_data.get('title', ''),
            "content": threat_data.get('description', ''),
            "source": "threat_intelligence",
            "timestamp": threat_data.get('created_at', ''),
            "tags": [
                threat_data.get('threat_type', 'unknown'),
                threat_data.get('severity', 'unknown'),
                "threat_intelligence"
            ]
        }
        
        await self.add_documents([document])
    
    async def add_cve_data(self, cve_data: Dict[str, Any]):
        """Add CVE data to knowledge base"""
        document = {
            "id": cve_data.get('cve_id', 'unknown'),
            "title": f"CVE: {cve_data.get('cve_id', 'unknown')}",
            "content": cve_data.get('description', ''),
            "source": "cve_database",
            "timestamp": cve_data.get('published_date', ''),
            "tags": [
                "cve",
                cve_data.get('severity', 'unknown'),
                *cve_data.get('affected_products', [])
            ]
        }
        
        await self.add_documents([document])
    
    async def add_analyst_logs(self, log_data: Dict[str, Any]):
        """Add analyst logs to knowledge base"""
        document = {
            "id": f"log_{log_data.get('id', 'unknown')}",
            "title": log_data.get('title', ''),
            "content": log_data.get('content', ''),
            "source": "analyst_logs",
            "timestamp": log_data.get('timestamp', ''),
            "tags": [
                "analyst_log",
                log_data.get('analyst_id', 'unknown'),
                *log_data.get('tags', [])
            ]
        }
        
        await self.add_documents([document])
    
    async def get_context_for_threat(self, threat_data: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Get relevant context for threat analysis"""
        # Create search query from threat data
        query = f"{threat_data.get('title', '')} {threat_data.get('description', '')}"
        
        # Search for relevant documents
        results = await self.search(query, top_k=10)
        
        # Filter by relevance score
        relevant_results = [r for r in results if r.get('score', 0) > 0.5]
        
        return relevant_results
    
    async def health_check(self) -> Dict[str, Any]:
        """Health check for RAG pipeline"""
        try:
            return {
                "status": "healthy",
                "embedding_model_available": self.embedding_model is not None,
                "index_size": len(self.metadata),
                "index_dimension": self.index.d if self.index else 0,
                "knowledge_base_path": str(self.knowledge_base_path)
            }
        except Exception as e:
            return {
                "status": "error",
                "error": str(e)
            }

# Global instance
rag_pipeline = RAGPipeline() 