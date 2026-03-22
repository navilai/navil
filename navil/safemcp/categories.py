"""
Canonical attack category taxonomy for Navil.
This file is the SINGLE SOURCE OF TRUTH for category names across:
  - navil-cloud-backend/app/services/honeypot_analyzer.py
  - navil/navil/safemcp/generator.py
  - navil/navil/safemcp/pool_converter.py

30 categories total: 16 existing + 14 agent-native.
"""

# ── Original 16 categories (do not rename) ──────────────────────────
EXISTING_CATEGORIES = [
    "prompt_injection",
    "data_exfiltration",
    "credential_access",
    "privilege_escalation",
    "reconnaissance",
    "command_and_control",
    "supply_chain",
    "denial_of_service",
    "lateral_movement",
    "persistence",
    "defense_evasion",
    "resource_hijacking",
    "code_execution",
    "social_engineering",
    "configuration_tampering",
    "information_disclosure",
]

# ── 14 new agent-native categories ──────────────────────────────────
AGENT_NATIVE_CATEGORIES = [
    "multimodal_smuggling",
    "handshake_hijacking",
    "rag_memory_poisoning",
    "agent_collusion",
    "cognitive_exploitation",
    "temporal_stateful",
    "output_weaponization",
    "tool_schema_injection",
    "context_window_manipulation",
    "model_supply_chain",
    "cross_tenant_leakage",
    "delegation_abuse",
    "feedback_loop_poisoning",
    "covert_channel",
]

# ── Combined canonical list ─────────────────────────────────────────
ALL_CATEGORIES = EXISTING_CATEGORIES + AGENT_NATIVE_CATEGORIES

# ── Category keyword mapping for classification ─────────────────────
# Used by honeypot_analyzer.py to classify anomaly_type strings.
CATEGORY_KEYWORDS = {
    # Existing
    "prompt_injection": ["prompt_inject", "injection", "jailbreak"],
    "data_exfiltration": ["exfil", "data_leak", "data_theft", "siphon"],
    "credential_access": ["credential", "cred_access", "password", "token_theft", "api_key"],
    "privilege_escalation": ["priv_esc", "escalat", "sudo", "admin_access"],
    "reconnaissance": ["recon", "enum", "fingerprint", "discovery", "scan", "probe"],
    "command_and_control": ["c2", "beacon", "callback", "heartbeat"],
    "supply_chain": ["supply_chain", "dependency", "package_inject", "typosquat"],
    "denial_of_service": ["dos", "flood", "exhaust", "rate_spike"],
    "lateral_movement": ["lateral", "pivot", "hop", "cross_server"],
    "persistence": ["persist", "backdoor", "implant", "cron_inject"],
    "defense_evasion": ["evasion", "obfuscat", "anti_detect", "camouflage"],
    "resource_hijacking": ["cryptomin", "resource_abuse", "compute_hijack"],
    "code_execution": ["code_exec", "rce", "eval_inject", "shell"],
    "social_engineering": ["social_eng", "phish", "pretext", "impersonat"],
    "configuration_tampering": ["config_tamper", "misconfig", "setting_change"],
    "information_disclosure": ["info_disclos", "leak", "exposure", "verbose_error"],
    # New agent-native
    "multimodal_smuggling": [
        "multimodal",
        "smuggl",
        "svg_inject",
        "steganograph",
        "pixel_inject",
        "ocr_attack",
    ],
    "handshake_hijacking": [
        "handshake",
        "mcp_init",
        "oauth_bypass",
        "pkce",
        "sse_pin",
        "transport_confus",
    ],
    "rag_memory_poisoning": [
        "rag_poison",
        "memory_poison",
        "embedding_manip",
        "retrieval_attack",
        "vector_db",
    ],
    "agent_collusion": ["collusion", "swarm_poison", "multi_agent", "agent_relay", "sybil"],
    "cognitive_exploitation": [
        "cognitive",
        "cot_hijack",
        "persona_drift",
        "bias_amplif",
        "attention_exploit",
    ],
    "temporal_stateful": [
        "temporal",
        "time_bomb",
        "session_persist",
        "state_corrupt",
        "checkpoint_roll",
    ],
    "output_weaponization": ["output_weapon", "code_backdoor", "citation_fabric", "report_bias"],
    "tool_schema_injection": ["schema_inject", "tool_schema", "default_exec", "inputschema"],
    "context_window_manipulation": [
        "context_flood",
        "context_displace",
        "summary_poison",
        "window_manip",
    ],
    "model_supply_chain": [
        "model_poison",
        "weight_backdoor",
        "lora_poison",
        "adapter_poison",
        "model_swap",
    ],
    "cross_tenant_leakage": ["cross_tenant", "tenant_leak", "shared_infra", "isolation_break"],
    "delegation_abuse": ["delegation", "authority_chain", "delegation_depth", "trust_launder"],
    "feedback_loop_poisoning": [
        "feedback_poison",
        "training_corrupt",
        "fine_tune_attack",
        "self_rag_amplif",
    ],
    "covert_channel": ["covert_channel", "stego_exfil", "encoding_channel", "side_channel_out"],
}

# ── Pool attack class → category mapping ────────────────────────────
# Maps the 11 mega pool attack classes to their primary honeypot category.
POOL_CLASS_TO_CATEGORY = {
    "Multi-Modal Smuggling": "multimodal_smuggling",
    "Handshake Hijacking": "handshake_hijacking",
    "RAG/Memory Poisoning": "rag_memory_poisoning",
    "Supply Chain/Discovery": "supply_chain",
    "Privilege Escalation": "privilege_escalation",
    "Anti-Forensics": "defense_evasion",
    "Agent Collusion & Multi-Agent Attacks": "agent_collusion",
    "Cognitive Architecture Exploitation": "cognitive_exploitation",
    "Temporal & Stateful Attacks": "temporal_stateful",
    "Output Manipulation & Weaponization": "output_weaponization",
    "Infrastructure & Runtime Attacks": "code_execution",
}
