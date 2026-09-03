"""
AI Capability Demo — Tracing Infrastructure
OpenTelemetry stubbing and LangSmith trace decorators.
AGENTS.md Section 2 & 4
"""

import os
import time
import functools
import logging
from typing import Any, Callable, Dict

logger = logging.getLogger(__name__)

def is_langsmith_synced() -> bool:
    """Check if LangSmith Tracing is active dynamically."""
    tracing = os.getenv("LANGCHAIN_TRACING_V2", "false").lower() == "true"
    api_key = os.getenv("LANGCHAIN_API_KEY", "")
    return tracing and bool(api_key)


def trace_agent(name: str) -> Callable:
    """Decorator to trace agent execution, capture latency, and log details.
    
    If LangSmith is active, it automatically integrates with langchain callbacks.
    """
    def decorator(func: Callable) -> Callable:
        @functools.wraps(func)
        def wrapper(*args, **kwargs) -> Any:
            start_time = time.time()
            agent_name = name or func.__name__
            
            logger.info("Executing Agent Trace: name=%s", agent_name)
            
            # Setup session audit log tracking
            import streamlit as st
            if "observability_traces" not in st.session_state:
                st.session_state.observability_traces = []
                
            try:
                result = func(*args, **kwargs)
                duration = (time.time() - start_time) * 1000
                
                # Append to st.session_state for Observability panel UI
                st.session_state.observability_traces.append({
                    "id": f"tr-{int(start_time)}",
                    "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(start_time)),
                    "agent": agent_name,
                    "status": "Success",
                    "duration_ms": duration,
                    "langsmith_synced": is_langsmith_synced(),
                    "error": None
                })
                
                return result
            except Exception as e:
                duration = (time.time() - start_time) * 1000
                st.session_state.observability_traces.append({
                    "id": f"tr-{int(start_time)}",
                    "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(start_time)),
                    "agent": agent_name,
                    "status": "Failed",
                    "duration_ms": duration,
                    "langsmith_synced": is_langsmith_synced(),
                    "error": str(e)
                })
                logger.error("Agent execution failed: name=%s error=%s", agent_name, str(e))
                raise e
        return wrapper
    return decorator
