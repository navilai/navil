"""RAG Endpoint honeypot profile -- mimics a vector DB with retrieval API.

Exposes tools that look like a Pinecone-like vector database providing
document ingestion, similarity search, and index management.
All responses are realistic-looking but contain only fake/dummy data.

Target categories: rag_memory_poisoning, feedback_loop_poisoning
"""

TOOLS = {
    "query_vectors": {
        "description": (
            "Query the vector index for semantically similar documents. "
            "Returns ranked results with scores, metadata, and text chunks. "
            "Supports filtering by namespace and metadata."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "query": {
                    "type": "string",
                    "description": "Natural language query or raw vector",
                },
                "top_k": {
                    "type": "integer",
                    "description": "Number of results to return (default: 10)",
                },
                "namespace": {
                    "type": "string",
                    "description": "Index namespace to search (default: default)",
                },
                "filter": {
                    "type": "object",
                    "description": 'Metadata filter (e.g. {"source": "docs"})',
                },
                "include_values": {
                    "type": "boolean",
                    "description": "Include embedding vectors in response (default: false)",
                },
            },
            "required": ["query"],
        },
        "response": {
            "status": "ok",
            "matches": [
                {
                    "id": "doc-4521",
                    "score": 0.94,
                    "metadata": {"source": "internal-docs", "page": 12, "updated": "2026-03-10"},
                    "text": "The API authentication uses JWT tokens signed with RS256...",
                },
                {
                    "id": "doc-3287",
                    "score": 0.89,
                    "metadata": {"source": "runbooks", "page": 3, "updated": "2026-02-28"},
                    "text": "Database connection strings are stored in AWS Secrets Manager...",
                },
                {
                    "id": "doc-1893",
                    "score": 0.85,
                    "metadata": {"source": "architecture", "page": 7, "updated": "2026-03-05"},
                    "text": "Service mesh uses mTLS between all internal services...",
                },
            ],
            "namespace": "default",
            "total_vectors": 125430,
        },
    },
    "upsert_vectors": {
        "description": (
            "Upsert documents or embeddings into the vector index. "
            "Accepts raw text (auto-embedded) or pre-computed vectors. "
            "Supports batch operations up to 100 records."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "vectors": {
                    "type": "array",
                    "description": "Array of {id, text, metadata} or {id, values, metadata}",
                },
                "namespace": {
                    "type": "string",
                    "description": "Target namespace (default: default)",
                },
                "batch_size": {
                    "type": "integer",
                    "description": "Batch size for processing (default: 50)",
                },
            },
            "required": ["vectors"],
        },
        "response": {
            "status": "ok",
            "upserted_count": 25,
            "namespace": "default",
            "index_size": 125455,
        },
    },
    "delete_vectors": {
        "description": (
            "Delete vectors from the index by ID, metadata filter, "
            "or delete all vectors in a namespace."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "ids": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": "Vector IDs to delete",
                },
                "filter": {
                    "type": "object",
                    "description": "Delete vectors matching this metadata filter",
                },
                "namespace": {
                    "type": "string",
                    "description": "Target namespace",
                },
                "delete_all": {
                    "type": "boolean",
                    "description": "Delete ALL vectors in namespace (default: false)",
                },
            },
        },
        "response": {
            "status": "ok",
            "deleted_count": 12,
            "namespace": "default",
        },
    },
    "list_indexes": {
        "description": (
            "List all vector indexes with their dimensions, record counts, "
            "and configuration. Includes storage and performance metrics."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "include_stats": {
                    "type": "boolean",
                    "description": "Include detailed index statistics (default: true)",
                },
            },
        },
        "response": {
            "status": "ok",
            "indexes": [
                {
                    "name": "prod-knowledge-base",
                    "dimension": 1536,
                    "metric": "cosine",
                    "total_vectors": 125430,
                    "namespaces": ["default", "internal-docs", "customer-data"],
                    "storage_mb": 892.5,
                    "replicas": 2,
                },
                {
                    "name": "customer-support-kb",
                    "dimension": 1536,
                    "metric": "cosine",
                    "total_vectors": 45200,
                    "namespaces": ["default", "tickets", "faq"],
                    "storage_mb": 321.7,
                    "replicas": 1,
                },
            ],
        },
    },
    "get_document": {
        "description": (
            "Retrieve a specific document by ID with its full text content, "
            "metadata, and embedding vector."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "id": {
                    "type": "string",
                    "description": "Document ID to retrieve",
                },
                "namespace": {
                    "type": "string",
                    "description": "Namespace containing the document",
                },
                "include_embedding": {
                    "type": "boolean",
                    "description": "Include the raw embedding vector (default: false)",
                },
            },
            "required": ["id"],
        },
        "response": {
            "status": "ok",
            "id": "doc-4521",
            "text": "The API authentication uses JWT tokens signed with RS256.",
            "metadata": {
                "source": "internal-docs",
                "page": 12,
                "author": "security-team",
                "classification": "internal",
                "updated": "2026-03-10",
            },
            "namespace": "default",
        },
    },
    "create_collection": {
        "description": (
            "Create a new vector collection with specified dimension, "
            "metric type, and replication settings."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "name": {
                    "type": "string",
                    "description": "Collection name",
                },
                "dimension": {
                    "type": "integer",
                    "description": "Embedding dimension (e.g. 1536 for text-embedding-3-small)",
                },
                "metric": {
                    "type": "string",
                    "enum": ["cosine", "euclidean", "dotproduct"],
                    "description": "Distance metric (default: cosine)",
                },
                "replicas": {
                    "type": "integer",
                    "description": "Number of replicas (default: 1)",
                },
            },
            "required": ["name", "dimension"],
        },
        "response": {
            "status": "ok",
            "created": True,
            "name": "new-collection",
            "dimension": 1536,
            "metric": "cosine",
            "replicas": 1,
        },
    },
}
