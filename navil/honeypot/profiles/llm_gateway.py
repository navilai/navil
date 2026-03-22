"""LLM Gateway honeypot profile -- mimics an AI Gateway endpoint.

Exposes tools that look like a real AI model gateway accepting
inference requests, managing API keys, and providing model routing.
All responses are realistic-looking but contain only fake/dummy data.

Target categories: cognitive_exploitation, context_window_manipulation
"""

TOOLS = {
    "chat_completion": {
        "description": (
            "Send a chat completion request to the gateway. Supports "
            "model selection, temperature, and tool use. Routes to "
            "the optimal backend provider automatically."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "model": {
                    "type": "string",
                    "description": "Model ID (e.g. 'gpt-4o', 'claude-sonnet-4')",
                },
                "messages": {
                    "type": "array",
                    "description": "Chat messages array",
                },
                "temperature": {
                    "type": "number",
                    "description": "Sampling temperature (default: 0.7)",
                },
                "max_tokens": {
                    "type": "integer",
                    "description": "Maximum tokens in response",
                },
                "tools": {
                    "type": "array",
                    "description": "Tool definitions for function calling",
                },
            },
            "required": ["model", "messages"],
        },
        "response": {
            "status": "ok",
            "id": "chatcmpl-honeypot-00001",
            "model": "gpt-4o-2024-11-20",
            "usage": {"prompt_tokens": 125, "completion_tokens": 64, "total_tokens": 189},
            "choices": [
                {
                    "message": {
                        "role": "assistant",
                        "content": "I can help with that request.",
                    },
                    "finish_reason": "stop",
                }
            ],
        },
    },
    "list_models": {
        "description": (
            "List all models available through the gateway with pricing, "
            "context window sizes, and current availability status."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "provider": {
                    "type": "string",
                    "enum": ["openai", "anthropic", "google", "meta", "all"],
                    "description": "Filter by provider (default: all)",
                },
                "capability": {
                    "type": "string",
                    "enum": ["chat", "embedding", "image", "code"],
                    "description": "Filter by capability",
                },
            },
        },
        "response": {
            "status": "ok",
            "models": [
                {
                    "id": "gpt-4o",
                    "provider": "openai",
                    "context_window": 128000,
                    "pricing_per_1k": {"input": 0.0025, "output": 0.01},
                    "status": "available",
                },
                {
                    "id": "claude-sonnet-4-20250514",
                    "provider": "anthropic",
                    "context_window": 200000,
                    "pricing_per_1k": {"input": 0.003, "output": 0.015},
                    "status": "available",
                },
                {
                    "id": "gemini-2.0-flash",
                    "provider": "google",
                    "context_window": 1000000,
                    "pricing_per_1k": {"input": 0.0001, "output": 0.0004},
                    "status": "available",
                },
            ],
        },
    },
    "get_api_key": {
        "description": (
            "Retrieve or rotate the gateway API key for a specific "
            "provider backend. Returns the active key and usage stats."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "provider": {
                    "type": "string",
                    "enum": ["openai", "anthropic", "google", "meta"],
                    "description": "Provider to get API key for",
                },
                "rotate": {
                    "type": "boolean",
                    "description": "Rotate the key and return the new one (default: false)",
                },
            },
            "required": ["provider"],
        },
        "response": {
            "status": "ok",
            "provider": "openai",
            "api_key": "sk-proj-FAKE_GATEWAY_KEY_XXXXXXXXXXXXXXXX",
            "usage_this_month": {"requests": 45230, "tokens": 12500000, "cost_usd": 187.50},
            "rate_limit": {"rpm": 10000, "tpm": 2000000},
        },
    },
    "get_usage_stats": {
        "description": (
            "Get detailed usage statistics for the gateway including "
            "per-model request counts, token usage, latency, and costs."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "period": {
                    "type": "string",
                    "enum": ["hour", "day", "week", "month"],
                    "description": "Time period for stats (default: day)",
                },
                "group_by": {
                    "type": "string",
                    "enum": ["model", "provider", "api_key", "endpoint"],
                    "description": "Grouping dimension (default: model)",
                },
            },
        },
        "response": {
            "status": "ok",
            "period": "day",
            "total_requests": 12450,
            "total_tokens": 3250000,
            "total_cost_usd": 48.75,
            "by_model": {
                "gpt-4o": {"requests": 5200, "tokens": 1500000, "avg_latency_ms": 850},
                "claude-sonnet-4-20250514": {
                    "requests": 4100,
                    "tokens": 1200000,
                    "avg_latency_ms": 920,
                },
                "gemini-2.0-flash": {"requests": 3150, "tokens": 550000, "avg_latency_ms": 340},
            },
        },
    },
    "configure_routing": {
        "description": (
            "Configure model routing rules for the gateway. Set fallback "
            "models, load balancing, and content-based routing policies."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "rules": {
                    "type": "array",
                    "description": "Routing rule definitions",
                },
                "fallback_model": {
                    "type": "string",
                    "description": "Fallback model when primary is unavailable",
                },
                "load_balance": {
                    "type": "boolean",
                    "description": "Enable load balancing across providers (default: false)",
                },
            },
        },
        "response": {
            "status": "ok",
            "rules_applied": 3,
            "fallback_model": "gpt-4o-mini",
            "load_balance": True,
            "effective_at": "2026-03-23T00:00:00Z",
        },
    },
}
