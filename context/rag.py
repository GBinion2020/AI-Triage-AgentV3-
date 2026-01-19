import chromadb
from chromadb.utils import embedding_functions
from typing import List, Dict, Optional

class MitreRAG:
    """
    Step 5: Conditional MITRE RAG.
    Only runs if specific techniques weren't found deterministically.
    """
    def __init__(self, persist_directory="./chroma_db"):
        """Initialize ChromaDB client with default SentenceTransformer embeddings."""
        try:
            self.client = chromadb.PersistentClient(path=persist_directory)
            
            # Use ChromaDB's default embedding function (all-MiniLM-L6-v2)
            self.embedding_function = embedding_functions.DefaultEmbeddingFunction()
            
            # Get existing collection (assume populated)
            self.attack_collection = self.client.get_or_create_collection(
                name="mitre_attack",
                embedding_function=self.embedding_function
            )
            self.operational = True
        except Exception as e:
            print(f"RAG Init Error: {e}")
            self.operational = False

    def query(self, alert_text: str, n_results: int = 3) -> List[Dict]:
        """
        Query MITRE ATT&CK techniques using semantic search.
        """
        if not self.operational:
            return []
            
        try:
            results = self.attack_collection.query(
                query_texts=[alert_text],
                n_results=n_results
            )
            
            techniques = []
            if results['documents'] and results['documents'][0]:
                for i, doc in enumerate(results['documents'][0]):
                    metadata = results['metadatas'][0][i] if results['metadatas'] else {}
                    techniques.append({
                        "id": metadata.get("technique_id", "Unknown"),
                        "name": metadata.get("name", "Unknown"),
                        "description": doc,
                        "tactics": metadata.get("tactics", ""),
                        "distance": results['distances'][0][i] if results.get('distances') else 0.0
                    })
            return techniques
            
        except Exception as e:
            print(f"RAG Query Error: {e}")
            return []
            
    def get_technique_by_id(self, technique_id: str) -> Optional[Dict]:
        """
        Retrieve a specific technique by ID.
        """
        if not self.operational:
            return None
            
        try:
            results = self.attack_collection.get(
                where={"technique_id": technique_id}
            )
            
            if results['documents']:
                metadata = results['metadatas'][0] if results['metadatas'] else {}
                return {
                    "id": technique_id,
                    "name": metadata.get("name", "Unknown"),
                    "description": results['documents'][0],
                    "tactics": metadata.get("tactics", "")
                }
            return None
        except Exception as e:
            print(f"RAG Get Error: {e}")
            return None
