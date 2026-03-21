"""Comprehensive tests for the static analysis subsystem.

Tests cover:
- Each of the 10 security check types individually
- Clean code producing no findings
- SARIF output from static analysis findings
- CLI command integration
- Directory scanning
- Language filtering
- Severity filtering
- Error handling for malformed files

NOTE: This test file contains INTENTIONALLY VULNERABLE code snippets
used as test fixtures for the security scanner. These snippets are
written to temporary files and analyzed -- they are never executed.
"""

from __future__ import annotations

import json
import subprocess as sp
import tempfile
from collections.abc import Generator
from pathlib import Path

import pytest

from navil.static_analysis.analyzer import StaticAnalyzer
from navil.types import Finding

try:
    import tree_sitter  # noqa: F401

    _has_tree_sitter = True
except ImportError:
    _has_tree_sitter = False

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture()
def tmp_dir() -> Generator[Path, None, None]:
    """Provide a temporary directory that is cleaned up after the test."""
    with tempfile.TemporaryDirectory() as d:
        yield Path(d)


def _write_py(tmp_dir: Path, code: str, name: str = "server.py") -> Path:
    """Write Python code to a temp file and return the path."""
    p = tmp_dir / name
    p.write_text(code)
    return p


def _write_js(tmp_dir: Path, code: str, name: str = "server.js") -> Path:
    """Write JavaScript code to a temp file and return the path."""
    p = tmp_dir / name
    p.write_text(code)
    return p


def _write_ts(tmp_dir: Path, code: str, name: str = "server.ts") -> Path:
    """Write TypeScript code to a temp file and return the path."""
    p = tmp_dir / name
    p.write_text(code)
    return p


def _find(findings: list[Finding], check_id: str) -> list[Finding]:
    """Filter findings by check ID prefix."""
    return [f for f in findings if f.id.startswith(check_id)]


# ---------------------------------------------------------------------------
# Check #1: Unsafe subprocess / code-evaluation
# ---------------------------------------------------------------------------


class TestSubprocessCheck:
    """Tests for unsafe subprocess and code-evaluation detection."""

    def test_subprocess_shell_true(self, tmp_dir: Path) -> None:
        # INTENTIONALLY VULNERABLE test fixture (not executed)
        code = "import subprocess\nsubprocess.run('ls', shell=True)\n"
        p = _write_py(tmp_dir, code)
        findings = StaticAnalyzer().analyze_file(str(p))
        hits = _find(findings, "SA-EXEC-SUBPROCESS-SHELL")
        assert len(hits) >= 1
        assert hits[0].severity == "CRITICAL"

    def test_subprocess_shell_false_no_finding(self, tmp_dir: Path) -> None:
        code = "import subprocess\nsubprocess.run(['ls', '-la'])\n"
        p = _write_py(tmp_dir, code)
        findings = StaticAnalyzer().analyze_file(str(p))
        hits = _find(findings, "SA-EXEC-SUBPROCESS-SHELL")
        assert len(hits) == 0

    def test_os_system(self, tmp_dir: Path) -> None:
        # INTENTIONALLY VULNERABLE test fixture
        code = "import os\nos.system('ls -la')\n"
        p = _write_py(tmp_dir, code)
        findings = StaticAnalyzer().analyze_file(str(p))
        hits = _find(findings, "SA-EXEC-OS-SYSTEM")
        assert len(hits) >= 1
        assert hits[0].severity == "CRITICAL"

    def test_code_eval_detected(self, tmp_dir: Path) -> None:
        # INTENTIONALLY VULNERABLE test fixture -- code evaluation detection target
        p = _write_py(tmp_dir, "x = eval('1+1')\n")
        findings = StaticAnalyzer().analyze_file(str(p))
        hits = _find(findings, "SA-EXEC-CODE-EVAL")
        assert len(hits) >= 1
        assert hits[0].severity == "HIGH"

    def test_code_exec_detected(self, tmp_dir: Path) -> None:
        # INTENTIONALLY VULNERABLE test fixture
        p = _write_py(tmp_dir, "exec('print(1)')\n")
        findings = StaticAnalyzer().analyze_file(str(p))
        hits = _find(findings, "SA-EXEC-CODE-EVAL")
        assert len(hits) >= 1

    def test_js_child_process_detection(self, tmp_dir: Path) -> None:
        # INTENTIONALLY VULNERABLE test fixture -- detection target
        code = 'const cp = require("child_process");\nchild_process.exec("ls");\n'
        p = _write_js(tmp_dir, code)
        findings = StaticAnalyzer().analyze_file(str(p))
        hits = _find(findings, "SA-EXEC-CHILD-PROCESS")
        assert len(hits) >= 1
        assert hits[0].severity == "CRITICAL"

    def test_js_code_eval(self, tmp_dir: Path) -> None:
        # INTENTIONALLY VULNERABLE test fixture
        code = 'const x = eval("1+1");\n'
        p = _write_js(tmp_dir, code)
        findings = StaticAnalyzer().analyze_file(str(p))
        hits = _find(findings, "SA-EXEC-CODE-EVAL")
        assert len(hits) >= 1


# ---------------------------------------------------------------------------
# Check #2: SQL injection
# ---------------------------------------------------------------------------


class TestSQLInjection:
    """Tests for SQL injection detection."""

    def test_fstring_sql(self, tmp_dir: Path) -> None:
        code = 'name = "test"\nquery = f"SELECT * FROM users WHERE name = \'{name}\'"\n'
        p = _write_py(tmp_dir, code)
        findings = StaticAnalyzer().analyze_file(str(p))
        hits = _find(findings, "SA-SQLI")
        assert len(hits) >= 1
        assert hits[0].severity == "CRITICAL"

    def test_format_sql(self, tmp_dir: Path) -> None:
        code = 'query = "SELECT * FROM users WHERE id = {}".format(user_id)\n'
        p = _write_py(tmp_dir, code)
        findings = StaticAnalyzer().analyze_file(str(p))
        hits = _find(findings, "SA-SQLI")
        assert len(hits) >= 1

    def test_concat_sql(self, tmp_dir: Path) -> None:
        code = 'query = "SELECT * FROM users WHERE id = " + user_id\n'
        p = _write_py(tmp_dir, code)
        findings = StaticAnalyzer().analyze_file(str(p))
        hits = _find(findings, "SA-SQLI")
        assert len(hits) >= 1

    def test_parameterized_no_finding(self, tmp_dir: Path) -> None:
        code = 'cursor.execute("SELECT * FROM users WHERE id = ?", (user_id,))\n'
        p = _write_py(tmp_dir, code)
        findings = StaticAnalyzer().analyze_file(str(p))
        hits = _find(findings, "SA-SQLI")
        assert len(hits) == 0

    def test_js_template_literal_sql(self, tmp_dir: Path) -> None:
        code = "const query = `SELECT * FROM users WHERE name = '${name}'`;\n"
        p = _write_js(tmp_dir, code)
        findings = StaticAnalyzer().analyze_file(str(p))
        hits = _find(findings, "SA-SQLI")
        assert len(hits) >= 1


# ---------------------------------------------------------------------------
# Check #3: Path traversal
# ---------------------------------------------------------------------------


class TestPathTraversal:
    """Tests for path traversal detection."""

    def test_open_fstring(self, tmp_dir: Path) -> None:
        code = 'filename = "test"\ndata = open(f"/data/{filename}")\n'
        p = _write_py(tmp_dir, code)
        findings = StaticAnalyzer().analyze_file(str(p))
        hits = _find(findings, "SA-PATH-TRAVERSAL")
        assert len(hits) >= 1
        assert hits[0].severity == "HIGH"

    def test_open_static_no_finding(self, tmp_dir: Path) -> None:
        code = 'data = open("/etc/config.json")\n'
        p = _write_py(tmp_dir, code)
        findings = StaticAnalyzer().analyze_file(str(p))
        hits = _find(findings, "SA-PATH-TRAVERSAL")
        assert len(hits) == 0

    def test_path_fstring(self, tmp_dir: Path) -> None:
        code = 'from pathlib import Path\np = Path(f"/data/{user_input}")\n'
        p = _write_py(tmp_dir, code)
        findings = StaticAnalyzer().analyze_file(str(p))
        hits = _find(findings, "SA-PATH-TRAVERSAL")
        assert len(hits) >= 1

    def test_js_fs_read(self, tmp_dir: Path) -> None:
        code = "const data = fs.readFileSync(userPath);\n"
        p = _write_js(tmp_dir, code)
        findings = StaticAnalyzer().analyze_file(str(p))
        hits = _find(findings, "SA-PATH-TRAVERSAL")
        assert len(hits) >= 1


# ---------------------------------------------------------------------------
# Check #4: Hardcoded secrets
# ---------------------------------------------------------------------------


class TestHardcodedSecrets:
    """Tests for hardcoded secrets detection."""

    def test_aws_key(self, tmp_dir: Path) -> None:
        code = 'AWS_KEY = "AKIA1234567890ABCDEF"\n'
        p = _write_py(tmp_dir, code)
        findings = StaticAnalyzer().analyze_file(str(p))
        hits = _find(findings, "SA-SECRET-AWS-KEY")
        assert len(hits) >= 1
        assert hits[0].severity == "CRITICAL"

    def test_generic_password(self, tmp_dir: Path) -> None:
        code = 'password = "my_super_secret_password"\n'
        p = _write_py(tmp_dir, code)
        findings = StaticAnalyzer().analyze_file(str(p))
        hits = _find(findings, "SA-SECRET-GENERIC-PASSWORD")
        assert len(hits) >= 1

    def test_api_key(self, tmp_dir: Path) -> None:
        code = 'api_key = "rk_prod_9xQ2mK7vL3nR8wP4jH6yT1bN"\n'
        p = _write_py(tmp_dir, code)
        findings = StaticAnalyzer().analyze_file(str(p))
        hits = _find(findings, "SA-SECRET-GENERIC-API-KEY")
        assert len(hits) >= 1

    def test_placeholder_no_finding(self, tmp_dir: Path) -> None:
        code = 'api_key = "your_api_key_here"\n'
        p = _write_py(tmp_dir, code)
        findings = StaticAnalyzer().analyze_file(str(p))
        hits = _find(findings, "SA-SECRET")
        assert len(hits) == 0

    def test_env_var_no_finding(self, tmp_dir: Path) -> None:
        code = 'api_key = os.environ.get("API_KEY")\n'
        p = _write_py(tmp_dir, code)
        findings = StaticAnalyzer().analyze_file(str(p))
        hits = _find(findings, "SA-SECRET")
        assert len(hits) == 0

    def test_github_token(self, tmp_dir: Path) -> None:
        code = 'token = "ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklm"\n'
        p = _write_py(tmp_dir, code)
        findings = StaticAnalyzer().analyze_file(str(p))
        hits = _find(findings, "SA-SECRET-GITHUB-TOKEN")
        assert len(hits) >= 1

    def test_jwt(self, tmp_dir: Path) -> None:
        code = 'token = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.abc"\n'
        p = _write_py(tmp_dir, code)
        findings = StaticAnalyzer().analyze_file(str(p))
        hits = _find(findings, "SA-SECRET-JWT")
        assert len(hits) >= 1


# ---------------------------------------------------------------------------
# Check #5: Missing input validation
# ---------------------------------------------------------------------------


class TestInputValidation:
    """Tests for missing input validation in tool handlers."""

    def test_handler_no_validation(self, tmp_dir: Path) -> None:
        code = (
            "def tool_handler(arguments):\n    name = arguments['name']\n    return name.upper()\n"
        )
        p = _write_py(tmp_dir, code)
        findings = StaticAnalyzer().analyze_file(str(p))
        hits = _find(findings, "SA-INPUT-VALIDATION")
        assert len(hits) >= 1
        assert hits[0].severity == "MEDIUM"

    def test_handler_with_validation(self, tmp_dir: Path) -> None:
        code = (
            "def tool_handler(arguments):\n"
            "    if not isinstance(arguments.get('name'), str):\n"
            "        raise ValueError('name must be a string')\n"
            "    return arguments['name'].upper()\n"
        )
        p = _write_py(tmp_dir, code)
        findings = StaticAnalyzer().analyze_file(str(p))
        hits = _find(findings, "SA-INPUT-VALIDATION")
        assert len(hits) == 0

    def test_non_handler_no_finding(self, tmp_dir: Path) -> None:
        code = "def process_data(data):\n    return data.upper()\n"
        p = _write_py(tmp_dir, code)
        findings = StaticAnalyzer().analyze_file(str(p))
        hits = _find(findings, "SA-INPUT-VALIDATION")
        assert len(hits) == 0


# ---------------------------------------------------------------------------
# Check #6: Unsafe deserialization
# ---------------------------------------------------------------------------


class TestDeserialization:
    """Tests for unsafe deserialization detection."""

    def test_pickle_loads(self, tmp_dir: Path) -> None:
        # INTENTIONALLY VULNERABLE -- detection target for scanner
        code = "import pickle\ndata = pickle.loads(raw_data)\n"
        p = _write_py(tmp_dir, code)
        findings = StaticAnalyzer().analyze_file(str(p))
        hits = _find(findings, "SA-DESERIALIZE")
        assert len(hits) >= 1
        assert hits[0].severity == "CRITICAL"

    def test_yaml_load_no_loader(self, tmp_dir: Path) -> None:
        code = "import yaml\nconfig = yaml.load(data)\n"
        p = _write_py(tmp_dir, code)
        findings = StaticAnalyzer().analyze_file(str(p))
        hits = _find(findings, "SA-DESERIALIZE")
        assert len(hits) >= 1

    def test_yaml_safe_load_no_finding(self, tmp_dir: Path) -> None:
        code = "import yaml\nconfig = yaml.safe_load(data)\n"
        p = _write_py(tmp_dir, code)
        findings = StaticAnalyzer().analyze_file(str(p))
        hits = _find(findings, "SA-DESERIALIZE")
        assert len(hits) == 0

    def test_yaml_load_with_safeloader_no_finding(self, tmp_dir: Path) -> None:
        code = "import yaml\nconfig = yaml.load(data, Loader=SafeLoader)\n"
        p = _write_py(tmp_dir, code)
        findings = StaticAnalyzer().analyze_file(str(p))
        hits = _find(findings, "SA-DESERIALIZE")
        assert len(hits) == 0

    def test_marshal_loads(self, tmp_dir: Path) -> None:
        code = "import marshal\ndata = marshal.loads(raw)\n"
        p = _write_py(tmp_dir, code)
        findings = StaticAnalyzer().analyze_file(str(p))
        hits = _find(findings, "SA-DESERIALIZE")
        assert len(hits) >= 1


# ---------------------------------------------------------------------------
# Check #7: Command injection
# ---------------------------------------------------------------------------


class TestCommandInjection:
    """Tests for command injection via tool arguments."""

    def test_fstring_subprocess(self, tmp_dir: Path) -> None:
        # INTENTIONALLY VULNERABLE test fixture
        code = (
            "import subprocess\n"
            "def run_cmd(name):\n"
            "    subprocess.run(f'echo {name}', shell=True)\n"
        )
        p = _write_py(tmp_dir, code)
        findings = StaticAnalyzer().analyze_file(str(p))
        hits = _find(findings, "SA-CMD-INJECTION")
        assert len(hits) >= 1
        assert hits[0].severity == "CRITICAL"

    @pytest.mark.skipif(
        not _has_tree_sitter,
        reason="tree-sitter not installed",
    )
    def test_concat_os_system(self, tmp_dir: Path) -> None:
        # INTENTIONALLY VULNERABLE test fixture — tests that navil detects this pattern
        code = "import os\nos.system('rm ' + filename)\n"
        p = _write_py(tmp_dir, code)
        findings = StaticAnalyzer().analyze_file(str(p))
        hits = _find(findings, "SA-CMD-INJECTION")
        assert len(hits) >= 1

    def test_safe_list_args_no_finding(self, tmp_dir: Path) -> None:
        code = "import subprocess\nsubprocess.run(['echo', name])\n"
        p = _write_py(tmp_dir, code)
        findings = StaticAnalyzer().analyze_file(str(p))
        hits = _find(findings, "SA-CMD-INJECTION")
        assert len(hits) == 0


# ---------------------------------------------------------------------------
# Check #8: Error handling
# ---------------------------------------------------------------------------


class TestErrorHandling:
    """Tests for missing/poor error handling."""

    def test_bare_except(self, tmp_dir: Path) -> None:
        code = "try:\n    x = 1\nexcept:\n    pass\n"
        p = _write_py(tmp_dir, code)
        findings = StaticAnalyzer().analyze_file(str(p))
        hits = _find(findings, "SA-ERROR-HANDLING-BARE-EXCEPT")
        assert len(hits) >= 1
        assert hits[0].severity == "MEDIUM"

    def test_specific_except_no_finding(self, tmp_dir: Path) -> None:
        code = "try:\n    x = 1\nexcept ValueError:\n    pass\n"
        p = _write_py(tmp_dir, code)
        findings = StaticAnalyzer().analyze_file(str(p))
        hits = _find(findings, "SA-ERROR-HANDLING-BARE-EXCEPT")
        assert len(hits) == 0

    @pytest.mark.skipif(
        not _has_tree_sitter,
        reason="tree-sitter not installed",
    )
    def test_handler_no_try(self, tmp_dir: Path) -> None:
        code = "def tool_handler(arguments):\n    return arguments['name'].upper()\n"
        p = _write_py(tmp_dir, code)
        findings = StaticAnalyzer().analyze_file(str(p))
        hits = _find(findings, "SA-ERROR-HANDLING-NO-TRY")
        assert len(hits) >= 1

    def test_handler_with_try(self, tmp_dir: Path) -> None:
        code = (
            "def tool_handler(arguments):\n"
            "    try:\n"
            "        return arguments['name'].upper()\n"
            "    except Exception as e:\n"
            "        return str(e)\n"
        )
        p = _write_py(tmp_dir, code)
        findings = StaticAnalyzer().analyze_file(str(p))
        hits = _find(findings, "SA-ERROR-HANDLING-NO-TRY")
        assert len(hits) == 0

    @pytest.mark.skipif(
        not _has_tree_sitter,
        reason="tree-sitter not installed",
    )
    def test_js_empty_catch(self, tmp_dir: Path) -> None:
        code = "try { x = 1; } catch (e) { }\n"
        p = _write_js(tmp_dir, code)
        findings = StaticAnalyzer().analyze_file(str(p))
        hits = _find(findings, "SA-ERROR-HANDLING-EMPTY-CATCH")
        assert len(hits) >= 1


# ---------------------------------------------------------------------------
# Check #9: Sensitive data in logs
# ---------------------------------------------------------------------------


class TestSensitiveLogs:
    """Tests for sensitive data in logging statements."""

    def test_password_in_log(self, tmp_dir: Path) -> None:
        code = 'import logging\nlogging.info("User password: %s", password)\n'
        p = _write_py(tmp_dir, code)
        findings = StaticAnalyzer().analyze_file(str(p))
        hits = _find(findings, "SA-SENSITIVE-LOG")
        assert len(hits) >= 1
        assert hits[0].severity == "HIGH"

    def test_token_in_print(self, tmp_dir: Path) -> None:
        code = 'print(f"Token: {api_token}")\n'
        p = _write_py(tmp_dir, code)
        findings = StaticAnalyzer().analyze_file(str(p))
        hits = _find(findings, "SA-SENSITIVE-LOG")
        assert len(hits) >= 1

    def test_safe_log_no_finding(self, tmp_dir: Path) -> None:
        code = 'import logging\nlogging.info("User %s logged in", username)\n'
        p = _write_py(tmp_dir, code)
        findings = StaticAnalyzer().analyze_file(str(p))
        hits = _find(findings, "SA-SENSITIVE-LOG")
        assert len(hits) == 0

    def test_js_console_log_token(self, tmp_dir: Path) -> None:
        code = 'console.log("Access token:", accessToken);\n'
        p = _write_js(tmp_dir, code)
        findings = StaticAnalyzer().analyze_file(str(p))
        hits = _find(findings, "SA-SENSITIVE-LOG")
        assert len(hits) >= 1


# ---------------------------------------------------------------------------
# Check #10: Insecure HTTP
# ---------------------------------------------------------------------------


class TestInsecureHTTP:
    """Tests for insecure HTTP URL detection."""

    def test_http_url(self, tmp_dir: Path) -> None:
        code = 'API_URL = "http://api.production.com/v1"\n'
        p = _write_py(tmp_dir, code)
        findings = StaticAnalyzer().analyze_file(str(p))
        hits = _find(findings, "SA-INSECURE-HTTP")
        assert len(hits) >= 1
        assert hits[0].severity == "MEDIUM"

    def test_https_no_finding(self, tmp_dir: Path) -> None:
        code = 'API_URL = "https://api.production.com/v1"\n'
        p = _write_py(tmp_dir, code)
        findings = StaticAnalyzer().analyze_file(str(p))
        hits = _find(findings, "SA-INSECURE-HTTP")
        assert len(hits) == 0

    def test_localhost_no_finding(self, tmp_dir: Path) -> None:
        code = 'DEV_URL = "http://localhost:8080/api"\n'
        p = _write_py(tmp_dir, code)
        findings = StaticAnalyzer().analyze_file(str(p))
        hits = _find(findings, "SA-INSECURE-HTTP")
        assert len(hits) == 0

    def test_test_file_skipped(self, tmp_dir: Path) -> None:
        code = 'API_URL = "http://api.production.com/v1"\n'
        p = _write_py(tmp_dir, code, name="test_server.py")
        findings = StaticAnalyzer().analyze_file(str(p))
        hits = _find(findings, "SA-INSECURE-HTTP")
        assert len(hits) == 0


# ---------------------------------------------------------------------------
# Clean code (no findings)
# ---------------------------------------------------------------------------


class TestCleanCode:
    """Verify that clean, well-written code produces no findings."""

    def test_clean_python(self, tmp_dir: Path) -> None:
        code = (
            "import json\n"
            "import yaml\n"
            "import subprocess\n"
            "from pathlib import Path\n"
            "\n"
            "API_URL = 'https://api.example.com/v1'\n"
            "\n"
            "def process_data(data: dict) -> dict:\n"
            "    config = yaml.safe_load(data.get('config', '{}'))\n"
            "    result = subprocess.run(['echo', 'hello'], capture_output=True)\n"
            "    p = Path('/safe/base/dir') / 'output.json'\n"
            "    with open(p) as f:\n"
            "        return json.load(f)\n"
        )
        p = _write_py(tmp_dir, code)
        findings = StaticAnalyzer().analyze_file(str(p))
        assert len(findings) == 0

    def test_clean_javascript(self, tmp_dir: Path) -> None:
        code = (
            'const https = require("https");\n'
            'const API_URL = "https://api.example.com/v1";\n'
            "\n"
            "function processData(data) {\n"
            "    try {\n"
            "        const result = JSON.parse(data);\n"
            "        console.log('Processing', result.id);\n"
            "        return result;\n"
            "    } catch (e) {\n"
            "        console.error('Parse failed:', e.message);\n"
            "        throw e;\n"
            "    }\n"
            "}\n"
        )
        p = _write_js(tmp_dir, code)
        findings = StaticAnalyzer().analyze_file(str(p))
        assert len(findings) == 0


# ---------------------------------------------------------------------------
# Analyzer features
# ---------------------------------------------------------------------------


class TestAnalyzerFeatures:
    """Tests for StaticAnalyzer configuration and behavior."""

    def test_severity_filter(self, tmp_dir: Path) -> None:
        code = (
            "import subprocess\n"
            "subprocess.run('ls', shell=True)\n"  # CRITICAL
            "try:\n"
            "    x = 1\n"
            "except:\n"  # MEDIUM
            "    pass\n"
        )
        p = _write_py(tmp_dir, code)

        # Without filter: finds both
        all_findings = StaticAnalyzer().analyze_file(str(p))
        assert len(all_findings) >= 2

        # With CRITICAL filter: only critical findings
        critical_only = StaticAnalyzer(severity_filter="CRITICAL").analyze_file(str(p))
        for f in critical_only:
            assert f.severity == "CRITICAL"

    def test_enabled_checks(self, tmp_dir: Path) -> None:
        code = (
            "import subprocess\n"
            "subprocess.run('ls', shell=True)\n"
            'password = "hunter2_secret_password"\n'
        )
        p = _write_py(tmp_dir, code)

        # Only run subprocess check
        findings = StaticAnalyzer(enabled_checks={"subprocess"}).analyze_file(str(p))
        for f in findings:
            assert f.id.startswith("SA-EXEC")

    def test_invalid_check_name(self) -> None:
        with pytest.raises(ValueError, match="Unknown check"):
            StaticAnalyzer(enabled_checks={"nonexistent_check"})

    def test_language_filter(self, tmp_dir: Path) -> None:
        py_code = 'password = "my_secret_password123"\n'
        js_code = 'const password = "my_secret_password123";\n'
        _write_py(tmp_dir, py_code, "server.py")
        _write_js(tmp_dir, js_code, "server.js")

        # Only analyze Python
        findings = StaticAnalyzer(languages={"python"}).analyze_path(str(tmp_dir))
        for f in findings:
            assert ".py:" in f.affected_field

    def test_directory_scan(self, tmp_dir: Path) -> None:
        # Create nested structure
        sub = tmp_dir / "src"
        sub.mkdir()
        _write_py(tmp_dir, 'password = "my_secret_password123"\n', "main.py")
        code2 = "import subprocess\nsubprocess.run('ls', shell=True)\n"
        (sub / "handler.py").write_text(code2)

        findings = StaticAnalyzer().analyze_path(str(tmp_dir))
        # Should find issues in both files
        paths = {f.affected_field.rsplit(":", 1)[0] for f in findings}
        assert any("main.py" in p for p in paths)
        assert any("handler.py" in p for p in paths)

    def test_nonexistent_path(self) -> None:
        with pytest.raises(FileNotFoundError):
            StaticAnalyzer().analyze_path("/nonexistent/path")

    def test_nonexistent_file(self) -> None:
        with pytest.raises(FileNotFoundError):
            StaticAnalyzer().analyze_file("/nonexistent/file.py")

    def test_node_modules_skipped(self, tmp_dir: Path) -> None:
        nm = tmp_dir / "node_modules" / "pkg"
        nm.mkdir(parents=True)
        code = 'const password = "my_secret_password123";\n'
        (nm / "index.js").write_text(code)

        findings = StaticAnalyzer().analyze_path(str(tmp_dir))
        assert len(findings) == 0

    def test_finding_source_is_static_analysis(self, tmp_dir: Path) -> None:
        code = "import subprocess\nsubprocess.run('ls', shell=True)\n"
        p = _write_py(tmp_dir, code)
        findings = StaticAnalyzer().analyze_file(str(p))
        for f in findings:
            assert f.source == "static_analysis"

    def test_affected_field_has_line_number(self, tmp_dir: Path) -> None:
        code = "import subprocess\nsubprocess.run('ls', shell=True)\n"
        p = _write_py(tmp_dir, code)
        findings = StaticAnalyzer().analyze_file(str(p))
        for f in findings:
            # affected_field should be "filepath:line_number"
            parts = f.affected_field.rsplit(":", 1)
            assert len(parts) == 2
            assert parts[1].isdigit()

    def test_unsupported_extension_skipped(self, tmp_dir: Path) -> None:
        (tmp_dir / "data.csv").write_text("a,b,c\n1,2,3\n")
        findings = StaticAnalyzer().analyze_path(str(tmp_dir))
        assert len(findings) == 0

    @pytest.mark.skipif(
        not _has_tree_sitter,
        reason="tree-sitter not installed",
    )
    def test_tree_sitter_property(self) -> None:
        analyzer = StaticAnalyzer()
        # Should be True since we installed tree-sitter
        assert analyzer.tree_sitter_available is True


# ---------------------------------------------------------------------------
# SARIF output integration
# ---------------------------------------------------------------------------


class TestSARIFOutput:
    """Tests for SARIF output from static analysis findings."""

    def test_sarif_from_findings(self, tmp_dir: Path) -> None:
        from navil.sarif import findings_to_sarif

        code = (
            "import subprocess\n"
            "subprocess.run('ls', shell=True)\n"
            'password = "my_secret_password123"\n'
        )
        p = _write_py(tmp_dir, code)
        findings = StaticAnalyzer().analyze_file(str(p))
        assert len(findings) > 0

        sarif = findings_to_sarif(findings)
        assert sarif["version"] == "2.1.0"
        assert len(sarif["runs"]) == 1

        run_data = sarif["runs"][0]
        assert run_data["tool"]["driver"]["name"] == "navil"
        assert len(run_data["results"]) == len(findings)

        # Each result should have ruleId, level, message
        for result in run_data["results"]:
            assert "ruleId" in result
            assert "level" in result
            assert "message" in result
            assert result["ruleId"].startswith("SA-")

    def test_sarif_string_output(self, tmp_dir: Path) -> None:
        from navil.sarif import findings_to_sarif_str

        code = "import subprocess\nsubprocess.run('ls', shell=True)\n"
        p = _write_py(tmp_dir, code)
        findings = StaticAnalyzer().analyze_file(str(p))

        sarif_str = findings_to_sarif_str(findings)
        parsed = json.loads(sarif_str)
        assert parsed["version"] == "2.1.0"
        assert len(parsed["runs"][0]["results"]) > 0


# ---------------------------------------------------------------------------
# CLI integration
# ---------------------------------------------------------------------------


class TestCLI:
    """Tests for the analyze CLI command."""

    def test_cli_text_output(self, tmp_dir: Path) -> None:
        code = "import subprocess\nsubprocess.run('ls', shell=True)\n"
        p = _write_py(tmp_dir, code)

        result = sp.run(
            ["python3", "-m", "navil", "analyze", str(p)],
            capture_output=True,
            text=True,
            cwd=str(Path(__file__).parent.parent),
        )
        assert "Static analysis of:" in result.stdout
        assert "SA-EXEC" in result.stdout

    def test_cli_json_output(self, tmp_dir: Path) -> None:
        code = "import subprocess\nsubprocess.run('ls', shell=True)\n"
        p = _write_py(tmp_dir, code)

        result = sp.run(
            ["python3", "-m", "navil", "analyze", str(p), "-f", "json"],
            capture_output=True,
            text=True,
            cwd=str(Path(__file__).parent.parent),
        )
        data = json.loads(result.stdout)
        assert data["status"] == "completed"
        assert data["total_findings"] > 0

    def test_cli_sarif_output(self, tmp_dir: Path) -> None:
        code = "import subprocess\nsubprocess.run('ls', shell=True)\n"
        p = _write_py(tmp_dir, code)

        result = sp.run(
            ["python3", "-m", "navil", "analyze", str(p), "-f", "sarif"],
            capture_output=True,
            text=True,
            cwd=str(Path(__file__).parent.parent),
        )
        sarif = json.loads(result.stdout)
        assert sarif["version"] == "2.1.0"

    def test_cli_severity_filter(self, tmp_dir: Path) -> None:
        code = (
            "import subprocess\n"
            "subprocess.run('ls', shell=True)\n"
            "try:\n"
            "    x = 1\n"
            "except:\n"
            "    pass\n"
        )
        p = _write_py(tmp_dir, code)

        result = sp.run(
            ["python3", "-m", "navil", "analyze", str(p), "-f", "json", "--severity", "CRITICAL"],
            capture_output=True,
            text=True,
            cwd=str(Path(__file__).parent.parent),
        )
        data = json.loads(result.stdout)
        for f in data["findings"]:
            assert f["severity"] == "CRITICAL"

    def test_cli_nonexistent_path(self, tmp_dir: Path) -> None:
        result = sp.run(
            ["python3", "-m", "navil", "analyze", "/nonexistent/path"],
            capture_output=True,
            text=True,
            cwd=str(Path(__file__).parent.parent),
        )
        assert result.returncode == 1

    def test_cli_output_file(self, tmp_dir: Path) -> None:
        code = "import subprocess\nsubprocess.run('ls', shell=True)\n"
        p = _write_py(tmp_dir, code)
        out_file = tmp_dir / "report.json"

        sp.run(
            ["python3", "-m", "navil", "analyze", str(p), "-f", "json", "-o", str(out_file)],
            capture_output=True,
            text=True,
            cwd=str(Path(__file__).parent.parent),
        )
        assert out_file.exists()
        data = json.loads(out_file.read_text())
        assert data["total_findings"] > 0


# ---------------------------------------------------------------------------
# TypeScript support
# ---------------------------------------------------------------------------


class TestTypeScript:
    """Tests for TypeScript source code analysis."""

    def test_ts_code_eval(self, tmp_dir: Path) -> None:
        # INTENTIONALLY VULNERABLE test fixture
        code = 'const x = eval("1+1");\n'
        p = _write_ts(tmp_dir, code)
        findings = StaticAnalyzer().analyze_file(str(p))
        hits = _find(findings, "SA-EXEC-CODE-EVAL")
        assert len(hits) >= 1

    def test_ts_template_sql(self, tmp_dir: Path) -> None:
        code = "const query = `SELECT * FROM users WHERE id = ${userId}`;\n"
        p = _write_ts(tmp_dir, code)
        findings = StaticAnalyzer().analyze_file(str(p))
        hits = _find(findings, "SA-SQLI")
        assert len(hits) >= 1

    def test_ts_http_url(self, tmp_dir: Path) -> None:
        code = 'const API_URL = "http://api.production.com/v1";\n'
        p = _write_ts(tmp_dir, code)
        findings = StaticAnalyzer().analyze_file(str(p))
        hits = _find(findings, "SA-INSECURE-HTTP")
        assert len(hits) >= 1
