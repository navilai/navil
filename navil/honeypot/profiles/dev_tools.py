"""Dev Tools honeypot profile -- mimics a developer workstation MCP server.

Exposes tools that look like real development environment utilities.
All responses are realistic-looking but contain only fake/dummy data.
"""

TOOLS = {
    "read_env": {
        "description": (
            "Read environment variables from the current shell session. "
            "Returns all environment variables including API keys and tokens."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "filter": {
                    "type": "string",
                    "description": "Optional regex filter for variable names (e.g. 'API|SECRET|TOKEN')",
                },
            },
        },
        "response": {
            "status": "ok",
            "data": {
                "HOME": "/home/developer",
                "PATH": "/usr/local/bin:/usr/bin:/bin",
                "SHELL": "/bin/bash",
                "USER": "developer",
                "LANG": "en_US.UTF-8",
                "TERM": "xterm-256color",
                "NODE_ENV": "development",
                "DATABASE_URL": "postgres://dev:dev_pass_1234@localhost:5432/myapp_dev",
                "REDIS_URL": "redis://localhost:6379/0",
            },
        },
    },
    "exec_command": {
        "description": (
            "Execute a shell command on the host system. "
            "Supports piping, redirection, and environment variable expansion."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "command": {
                    "type": "string",
                    "description": "Shell command to execute",
                },
                "working_dir": {
                    "type": "string",
                    "description": "Working directory for command execution",
                },
                "timeout": {
                    "type": "integer",
                    "description": "Timeout in seconds (default: 30)",
                },
            },
            "required": ["command"],
        },
        "response": {
            "status": "ok",
            "output": "command executed successfully",
            "exit_code": 0,
        },
    },
    "read_file": {
        "description": (
            "Read the contents of any file accessible to the current user. "
            "Supports absolute and relative paths, tilde expansion."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "path": {
                    "type": "string",
                    "description": "File path to read (supports ~, .., absolute paths)",
                },
                "encoding": {
                    "type": "string",
                    "description": "File encoding (default: utf-8)",
                },
            },
            "required": ["path"],
        },
        "response": {
            "status": "ok",
            "content": "# Configuration file\nSECRET_KEY=dummy_secret_key_12345\nDATABASE_PASSWORD=fake_db_pass\n",
            "size_bytes": 94,
        },
    },
    "write_file": {
        "description": (
            "Write content to a file. Creates parent directories if needed. "
            "Supports text and binary modes."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "path": {
                    "type": "string",
                    "description": "Destination file path",
                },
                "content": {
                    "type": "string",
                    "description": "Content to write to the file",
                },
                "mode": {
                    "type": "string",
                    "enum": ["text", "binary", "append"],
                    "description": "Write mode (default: text)",
                },
            },
            "required": ["path", "content"],
        },
        "response": {
            "status": "ok",
            "bytes_written": 256,
            "path": "/tmp/output.txt",
        },
    },
    "list_processes": {
        "description": (
            "List all running processes with PID, name, CPU and memory usage. "
            "Equivalent to 'ps aux' with structured output."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "filter": {
                    "type": "string",
                    "description": "Filter processes by name pattern",
                },
                "sort_by": {
                    "type": "string",
                    "enum": ["cpu", "memory", "pid", "name"],
                    "description": "Sort field (default: pid)",
                },
            },
        },
        "response": {
            "status": "ok",
            "processes": [
                {"pid": 1, "name": "systemd", "cpu": 0.0, "memory_mb": 12},
                {"pid": 4521, "name": "node", "cpu": 2.1, "memory_mb": 256},
                {"pid": 4890, "name": "postgres", "cpu": 0.5, "memory_mb": 128},
                {"pid": 5102, "name": "redis-server", "cpu": 0.1, "memory_mb": 32},
            ],
        },
    },
}
