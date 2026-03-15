"""Database Admin honeypot profile -- mimics a database management MCP server.

Exposes tools that look like they provide full database admin access.
All returned data is realistic but entirely fabricated.
"""

TOOLS = {
    "query_db": {
        "description": (
            "Execute a SQL query against the database. Supports SELECT, "
            "INSERT, UPDATE, DELETE. Returns results as structured data."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "query": {
                    "type": "string",
                    "description": "SQL query to execute",
                },
                "database": {
                    "type": "string",
                    "description": "Target database name (default: primary)",
                },
                "params": {
                    "type": "array",
                    "description": "Parameterized query values",
                },
            },
            "required": ["query"],
        },
        "response": {
            "status": "ok",
            "rows_affected": 5,
            "data": [
                {"id": 1, "username": "alice", "email": "alice@example.com", "role": "admin"},
                {"id": 2, "username": "bob", "email": "bob@example.com", "role": "user"},
                {"id": 3, "username": "charlie", "email": "charlie@example.com", "role": "user"},
            ],
        },
    },
    "list_tables": {
        "description": (
            "List all tables in the database with row counts, sizes, "
            "and last modified timestamps."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "database": {
                    "type": "string",
                    "description": "Target database name",
                },
                "schema": {
                    "type": "string",
                    "description": "Schema name (default: public)",
                },
            },
        },
        "response": {
            "status": "ok",
            "tables": [
                {"name": "users", "rows": 15420, "size_mb": 12.5, "last_modified": "2026-03-15"},
                {"name": "orders", "rows": 89234, "size_mb": 45.2, "last_modified": "2026-03-15"},
                {"name": "sessions", "rows": 5621, "size_mb": 2.1, "last_modified": "2026-03-15"},
                {"name": "api_keys", "rows": 342, "size_mb": 0.5, "last_modified": "2026-03-14"},
                {"name": "audit_log", "rows": 234567, "size_mb": 89.3, "last_modified": "2026-03-15"},
            ],
        },
    },
    "dump_schema": {
        "description": (
            "Dump the full database schema including tables, columns, indexes, "
            "constraints, and foreign key relationships."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "database": {
                    "type": "string",
                    "description": "Target database name",
                },
                "format": {
                    "type": "string",
                    "enum": ["sql", "json", "yaml"],
                    "description": "Output format (default: sql)",
                },
            },
        },
        "response": {
            "status": "ok",
            "format": "sql",
            "schema": (
                "CREATE TABLE users (id SERIAL PRIMARY KEY, username VARCHAR(255) NOT NULL, "
                "email VARCHAR(255) UNIQUE, role VARCHAR(50) DEFAULT 'user', "
                "password_hash VARCHAR(255), created_at TIMESTAMP DEFAULT NOW());\n"
                "CREATE TABLE api_keys (id SERIAL PRIMARY KEY, user_id INT REFERENCES users(id), "
                "key_hash VARCHAR(255), scopes TEXT[], created_at TIMESTAMP DEFAULT NOW());"
            ),
        },
    },
    "export_data": {
        "description": (
            "Export an entire table or query result to CSV or JSON format. "
            "Useful for backups and data migration."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "table": {
                    "type": "string",
                    "description": "Table name to export",
                },
                "query": {
                    "type": "string",
                    "description": "Custom query (alternative to table)",
                },
                "format": {
                    "type": "string",
                    "enum": ["csv", "json", "parquet"],
                    "description": "Export format (default: json)",
                },
                "limit": {
                    "type": "integer",
                    "description": "Maximum rows to export (default: unlimited)",
                },
            },
        },
        "response": {
            "status": "ok",
            "format": "json",
            "row_count": 100,
            "size_bytes": 25600,
            "data": "[exported data truncated for display]",
        },
    },
    "create_user": {
        "description": (
            "Create a new database user with specified privileges. "
            "Supports role-based access control."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "username": {
                    "type": "string",
                    "description": "Username for the new database user",
                },
                "password": {
                    "type": "string",
                    "description": "Password for the new user",
                },
                "roles": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": "List of roles to grant (e.g. ['SELECT', 'INSERT'])",
                },
            },
            "required": ["username", "password"],
        },
        "response": {
            "status": "ok",
            "username": "new_user",
            "created": True,
            "privileges": ["SELECT", "INSERT"],
        },
    },
    "grant_permissions": {
        "description": (
            "Grant database permissions to a user. "
            "Supports granular table-level and column-level permissions."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "user": {
                    "type": "string",
                    "description": "Target user to grant permissions to",
                },
                "permissions": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": "Permissions to grant (e.g. ['SELECT', 'ALL PRIVILEGES'])",
                },
                "scope": {
                    "type": "string",
                    "description": "Scope of grant (e.g. 'public.*', 'users')",
                },
            },
            "required": ["user", "permissions"],
        },
        "response": {
            "status": "ok",
            "granted": True,
            "user": "target_user",
            "permissions": ["ALL PRIVILEGES"],
            "scope": "public.*",
        },
    },
}
