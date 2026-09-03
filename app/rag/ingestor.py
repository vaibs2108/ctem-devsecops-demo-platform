"""
RAGIngestor — Robust data chunking, embedding, and upserting into FAISS Index.
Supports full-featured semantic search with offline fallback.
AGENTS.md Section 4, 6.2 & 10.3.
"""
from __future__ import annotations

import hashlib
import logging
import os
from typing import Dict, List, Any, Optional

import numpy as np
import pandas as pd
from dotenv import load_dotenv
from openai import OpenAI

from app.rag.indexes import FAISSIndexManager

load_dotenv(override=True)
logger = logging.getLogger(__name__)


class RAGIngestor:
    """Handles vector generation and data ingestion into FAISS."""

    def __init__(self, faiss_manager: Optional[FAISSIndexManager] = None) -> None:
        """Initialise the RAG ingestor using FAISSIndexManager."""
        self.openai_key = os.getenv("OPENAI_API_KEY", "")
        self.manager = faiss_manager or FAISSIndexManager()
        logger.info("Initialized FAISS-backed RAG Ingestor successfully.")

    def _embed_texts(self, texts: List[str]) -> List[List[float]]:
        """Generate embeddings using text-embedding-3-small or fallback to offline mock embeddings."""
        if self.openai_key:
            try:
                # Batched OpenAI embeddings
                client = OpenAI(api_key=self.openai_key)
                response = client.embeddings.create(
                    input=texts,
                    model="text-embedding-3-small"
                )
                return [item.embedding for item in response.data]
            except Exception as exc:
                logger.warning("OpenAI embedding API failed (%s). Falling back to offline mock embeddings.", exc)

        # Robust, deterministic offline mock embeddings
        # Generate 1536-dim vector by hashing the text so identical texts have identical embeddings
        logger.debug("Generating deterministic mock embeddings offline.")
        embeddings = []
        for text in texts:
            # Seed based on MD5 hash of text
            hasher = hashlib.md5(text.encode("utf-8"))
            seed_val = int(hasher.hexdigest(), 16) % (2**32 - 1)
            rng = np.random.default_rng(seed_val)
            
            # Generate cosine-normalised vector of length 1536
            vec = rng.normal(0, 1, 1536)
            norm = np.linalg.norm(vec)
            vec = (vec / norm if norm > 0 else vec).tolist()
            embeddings.append(vec)
        return embeddings

    def ingest_dataframe(
        self,
        df: pd.DataFrame,
        collection_name: str,
        data_source: str = "synthetic",
        use_case: str = "",
        metadata_extra: Optional[Dict[str, Any]] = None,
    ) -> int:
        """Serialise DataFrame rows into text chunks, embed, and upsert to FAISS."""
        if df.empty:
            logger.warning("Empty DataFrame passed to RAGIngestor.")
            return 0

        logger.info("Ingesting %d rows into FAISS collection: %s", len(df), collection_name)
        
        texts = []
        payloads = []

        # Convert each row to an enriched text representation
        for idx, row in df.iterrows():
            row_dict = row.to_dict()
            
            # Text chunk: detailed natural language description of the row
            row_text = f"Security data record in collection {collection_name}.\n"
            for col, val in row_dict.items():
                row_text += f"{col}: {val}\n"
            
            texts.append(row_text)
            
            # Build metadata payload
            payload = {
                "text_content": row_text,
                "data_source": data_source,
                "use_case": use_case,
                "row_index": idx,
                **(metadata_extra or {})
            }
            # Stringify complex dicts/lists for flat storage
            for col, val in row_dict.items():
                if isinstance(val, (dict, list)):
                    payload[col] = str(val)
                elif pd.isna(val):
                    payload[col] = None
                else:
                    payload[col] = val
                    
            payloads.append(payload)

        # Batch embedding & upserting (batch size 100)
        batch_size = 100
        count = 0
        
        for i in range(0, len(texts), batch_size):
            batch_texts = texts[i:i + batch_size]
            batch_payloads = payloads[i:i + batch_size]
            
            try:
                embeddings = self._embed_texts(batch_texts)
                self.manager.add(
                    index_name=collection_name,
                    texts=batch_texts,
                    metadata=batch_payloads,
                    embeddings=embeddings
                )
                count += len(batch_texts)
            except Exception as exc:
                logger.error("Failed to upsert FAISS batch: %s", exc)
                
        logger.info("Successfully ingested %d vectors into FAISS index %s.", count, collection_name)
        return count

    def ingest_text_chunks(
        self,
        chunks: List[str],
        collection_name: str,
        metadata: Dict[str, Any],
    ) -> int:
        """Ingest plain text chunks directly with provided metadata."""
        if not chunks:
            return 0
            
        try:
            embeddings = self._embed_texts(chunks)
            payloads = []
            for idx, text in enumerate(chunks):
                payload = {
                    "text_content": text,
                    "chunk_index": idx,
                    **metadata
                }
                payloads.append(payload)
            self.manager.add(
                index_name=collection_name,
                texts=chunks,
                metadata=payloads,
                embeddings=embeddings
            )
            return len(chunks)
        except Exception as exc:
            logger.error("Failed to ingest text chunks into FAISS: %s", exc)
            return 0

    def get_collection_info(self, collection_name: str) -> Dict[str, Any]:
        """Return collection metadata: vector count, status."""
        try:
            ntotal = self.manager.indexes[collection_name].ntotal
            return {
                "status": "green",
                "vectors_count": ntotal,
                "points_count": ntotal,
            }
        except Exception:
            return {"status": "error", "vectors_count": 0, "points_count": 0}
