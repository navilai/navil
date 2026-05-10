# PyPI Listing Optimization

**Current version:** 0.2.1
**Package:** https://pypi.org/project/navil/

---

## Current State

The existing `pyproject.toml` is functional but has room for improvement in discoverability and presentation on PyPI.

## Recommended Changes

### 1. Improve `description` (one-liner shown in search results)

**Current:**
```
description = "Security gateway for MCP servers"
```

**Suggested:**
```
description = "Open-source agent governance middleware -- runtime security proxy, policy enforcement, and threat intelligence for MCP tool calls"
```

**Rationale:** The current description is too generic. The improved version includes key differentiators (runtime, policy, threat intel) and the term "agent governance" which is the emerging category name. It also mentions MCP explicitly for search relevance.

### 2. Add more classifiers

**Current classifiers are good but missing some important ones.**

Add these classifiers to the existing list:

```toml
classifiers = [
    # --- KEEP EXISTING ---
    "Development Status :: 3 - Alpha",
    "Intended Audience :: Developers",
    "Intended Audience :: System Administrators",
    "Operating System :: OS Independent",
    "Programming Language :: Python :: 3",
    "Programming Language :: Python :: 3.10",
    "Programming Language :: Python :: 3.11",
    "Programming Language :: Python :: 3.12",
    "Programming Language :: Python :: 3.13",
    "Topic :: Security",
    "Topic :: System :: Monitoring",
    "Typing :: Typed",
    # --- ADD THESE ---
    "Development Status :: 4 - Beta",                          # upgrade from Alpha if appropriate
    "Intended Audience :: Information Technology",
    "Intended Audience :: Financial and Insurance Industry",    # regulated industries
    "License :: OSI Approved :: Apache Software License",
    "Programming Language :: Rust",                            # Rust proxy component
    "Topic :: Security :: Cryptography",                       # JWT, HMAC
    "Topic :: Software Development :: Quality Assurance",
    "Topic :: Software Development :: Testing",                # pentest, scanning
    "Topic :: System :: Systems Administration",
    "Framework :: FastAPI",                                    # cloud component
]
```

**Note:** Remove `"Development Status :: 3 - Alpha"` when adding `"Development Status :: 4 - Beta"`. Only one status classifier should be present.

### 3. Expand keywords for discoverability

**Current:**
```toml
keywords = [
    "mcp",
    "security",
    "supply-chain",
    "ai-agents",
    "credentials",
    "policy-engine",
    "anomaly-detection",
]
```

**Suggested:**
```toml
keywords = [
    "mcp",
    "mcp-server",
    "mcp-security",
    "security",
    "ai-agents",
    "agent-governance",
    "llm-security",
    "supply-chain",
    "credentials",
    "policy-engine",
    "anomaly-detection",
    "threat-intelligence",
    "runtime-security",
    "tool-calling",
    "prompt-injection",
]
```

**Rationale:** Adds high-search-volume terms like "llm-security", "agent-governance", "prompt-injection", and "mcp-server" that users are likely searching for.

### 4. Improve project URLs

**Current:**
```toml
[project.urls]
Homepage = "https://github.com/navilai/navil"
Repository = "https://github.com/navilai/navil"
Documentation = "https://github.com/navilai/navil#readme"
Issues = "https://github.com/navilai/navil/issues"
Changelog = "https://github.com/navilai/navil/blob/main/CHANGELOG.md"
```

**Suggested:**
```toml
[project.urls]
Homepage = "https://navil.ai"
Repository = "https://github.com/navilai/navil"
Documentation = "https://github.com/navilai/navil#readme"
"Bug Tracker" = "https://github.com/navilai/navil/issues"
Changelog = "https://github.com/navilai/navil/blob/main/CHANGELOG.md"
"Live Demo" = "https://navil.ai/radar"
"Security Policy" = "https://github.com/navilai/navil/blob/main/SECURITY.md"
"Data Collection Policy" = "https://github.com/navilai/navil/blob/main/DATA_COLLECTION.md"
```

**Changes:**
- `Homepage` now points to navil.ai (the product site) instead of GitHub
- `Issues` renamed to `Bug Tracker` (PyPI recognizes this key and shows a special icon)
- Added `Live Demo` linking to the threat radar
- Added `Security Policy` and `Data Collection Policy` for trust signals

### 5. Verify long_description renders correctly

The `readme = "README.md"` field is already set, which means PyPI will render the README as the long description. Verify the following:

```bash
# Build and check rendering locally
pip install build twine
python -m build
twine check dist/*

# Preview the rendered README
pip install readme-renderer
python -m readme_renderer README.md -o /tmp/navil-readme.html
```

**Potential issue:** The README uses HTML tags (`<p align="center">`, `<table>`, `<details>`) which PyPI's renderer may not fully support. Test with `twine check` and consider adding a `long_description_content_type` if not already inferred:

```toml
[project]
readme = {file = "README.md", content-type = "text/markdown"}
```

### 6. Summary of all changes to `pyproject.toml`

```toml
[project]
name = "navil"
version = "0.2.1"
description = "Open-source agent governance middleware -- runtime security proxy, policy enforcement, and threat intelligence for MCP tool calls"
readme = {file = "README.md", content-type = "text/markdown"}
requires-python = ">=3.10"
license = "Apache-2.0"
authors = [
    {name = "Pantheon Lab Pte Ltd"},
]
keywords = [
    "mcp",
    "mcp-server",
    "mcp-security",
    "security",
    "ai-agents",
    "agent-governance",
    "llm-security",
    "supply-chain",
    "credentials",
    "policy-engine",
    "anomaly-detection",
    "threat-intelligence",
    "runtime-security",
    "tool-calling",
    "prompt-injection",
]
classifiers = [
    "Development Status :: 4 - Beta",
    "Intended Audience :: Developers",
    "Intended Audience :: System Administrators",
    "Intended Audience :: Information Technology",
    "License :: OSI Approved :: Apache Software License",
    "Operating System :: OS Independent",
    "Programming Language :: Python :: 3",
    "Programming Language :: Python :: 3.10",
    "Programming Language :: Python :: 3.11",
    "Programming Language :: Python :: 3.12",
    "Programming Language :: Python :: 3.13",
    "Programming Language :: Rust",
    "Topic :: Security",
    "Topic :: Security :: Cryptography",
    "Topic :: Software Development :: Quality Assurance",
    "Topic :: Software Development :: Testing",
    "Topic :: System :: Monitoring",
    "Topic :: System :: Systems Administration",
    "Framework :: FastAPI",
    "Typing :: Typed",
]

# ... (dependencies unchanged) ...

[project.urls]
Homepage = "https://navil.ai"
Repository = "https://github.com/navilai/navil"
Documentation = "https://github.com/navilai/navil#readme"
"Bug Tracker" = "https://github.com/navilai/navil/issues"
Changelog = "https://github.com/navilai/navil/blob/main/CHANGELOG.md"
"Live Demo" = "https://navil.ai/radar"
"Security Policy" = "https://github.com/navilai/navil/blob/main/SECURITY.md"
"Data Collection Policy" = "https://github.com/navilai/navil/blob/main/DATA_COLLECTION.md"
```
