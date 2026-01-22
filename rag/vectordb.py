import chromadb
from chromadb.utils import embedding_functions
import requests


class MITREVectorDB:
    def __init__(self, persist_directory="./chroma_db"):
        """Initialize ChromaDB client with default SentenceTransformer embeddings."""
        self.client = chromadb.PersistentClient(path=persist_directory)
        
        # Use ChromaDB's default embedding function (all-MiniLM-L6-v2)
        # More reliable than Ollama API calls
        self.embedding_function = embedding_functions.DefaultEmbeddingFunction()
        
        # Get or create collections
        self.attack_collection = self.client.get_or_create_collection(
            name="mitre_attack",
            embedding_function=self.embedding_function,
            metadata={"description": "MITRE ATT&CK techniques with embeddings"}
        )
        
        self.defend_collection = self.client.get_or_create_collection(
            name="mitre_defend",
            metadata={"description": "MITRE D3FEND countermeasures (no embeddings)"}
        )
        
        self.feedback_collection = self.client.get_or_create_collection(
            name="feedback_loop",
            embedding_function=self.embedding_function,
            metadata={"description": "Analyst feedback and investigation close notes"}
        )
    
    def query_attack_techniques(self, query_text: str, n_results: int = 3) -> list:
        """
        Query MITRE ATT&CK techniques using semantic search.
        
        Args:
            query_text: The search query (e.g., alert description)
            n_results: Number of results to return
            
        Returns:
            List of relevant technique dictionaries
        """
        results = self.attack_collection.query(
            query_texts=[query_text],
            n_results=n_results
        )
        
        # Format results
        techniques = []
        if results['documents'] and results['documents'][0]:
            for i, doc in enumerate(results['documents'][0]):
                metadata = results['metadatas'][0][i] if results['metadatas'] else {}
                techniques.append({
                    "id": metadata.get("technique_id", "Unknown"),
                    "name": metadata.get("name", "Unknown"),
                    "description": doc,
                    "tactics": metadata.get("tactics", ""),
                    "distance": results['distances'][0][i] if results.get('distances') else None
                })
        
        return techniques
    
    def get_technique_by_id(self, technique_id: str) -> dict:
        """
        Retrieve a specific technique by ID (e.g., T1059).
        
        Args:
            technique_id: MITRE technique ID
            
        Returns:
            Technique dictionary or None
        """
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

    def query_feedback(self, query_text: str, n_results: int = 2) -> list:
        """Query past analyst feedback using semantic search."""
        results = self.feedback_collection.query(
            query_texts=[query_text],
            n_results=n_results
        )
        
        feedback = []
        if results['documents'] and results['documents'][0]:
            for i, doc in enumerate(results['documents'][0]):
                metadata = results['metadatas'][0][i] if results['metadatas'] else {}
                feedback.append({
                    "alert_id": metadata.get("alert_id", "Unknown"),
                    "verdict": metadata.get("verdict", "Unknown"),
                    "notes": doc,
                    "artifacts": metadata.get("artifacts", "[]"),
                    "distance": results['distances'][0][i] if results.get('distances') else None
                })
        return feedback



class OllamaEmbedding(embedding_functions.EmbeddingFunction):
    """Custom embedding function for Ollama's mxbai-embed-large model."""
    
    def __init__(self, model: str = "mxbai-embed-large:latest", url: str = "http://localhost:11434/api/embeddings"):
        self._model = model
        self._url = url
    
    def __call__(self, input: list[str]) -> list[list[float]]:
        """Generate embeddings for a list of texts."""
        embeddings = []
        
        for idx, text in enumerate(input):
            try:
                response = requests.post(
                    self._url,
                    json={"model": self._model, "prompt": text},
                    timeout=60
                )
                
                # Check for HTTP errors
                if response.status_code != 200:
                    print(f"WARNING: Ollama returned {response.status_code} for text {idx}")
                    print(f"Response: {response.text[:500]}")
                    # Return empty embedding as fallback
                    embeddings.append([0.0] * 1024)
                    continue
                
                # Parse JSON
                try:
                    data = response.json()
                except Exception as e:
                    print(f"WARNING: Failed to parse JSON for text {idx}: {e}")
                    print(f"Response text: {response.text[:500]}")
                    embeddings.append([0.0] * 1024)
                    continue
                
                embedding = data.get("embedding", [])
                if not embedding:
                    print(f"WARNING: Empty embedding for text {idx}")
                    embeddings.append([0.0] * 1024)
                else:
                    embeddings.append(embedding)
                    
            except requests.exceptions.Timeout:
                print(f"WARNING: Timeout for text {idx}, using zero embedding")
                embeddings.append([0.0] * 1024)
            except Exception as e:
                print(f"WARNING: Error processing text {idx}: {e}")
                embeddings.append([0.0] * 1024)
        
        return embeddings
