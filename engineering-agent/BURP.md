# Burp MCP

HYDRA includes an MCP client for the official
[PortSwigger Burp MCP extension](https://github.com/PortSwigger/mcp-server).
`requirements-agent.txt` installs the client dependency by default. Burp Suite
and its extension are separate applications.

1. Load the official extension in Burp Suite, following its README or BApp Store listing.
2. In Burp's **MCP** tab, enable the server. The documented SSE endpoint defaults
   to `http://127.0.0.1:9876`. Set `BURP_MCP_URL` locally if your extension uses a
   different port/path (for example `/sse`).
3. Run `python -m hydra burp` or type `/burp` to check the MCP handshake and list
   the tools actually exposed by your running extension.
4. Ask HYDRA to inspect the authorized Burp project. The model can use
   `burp_status`, `burp_tools` and `burp_call`; schemas come from the live server.

Each `burp_call` asks for approval, including history reads. `--allow-run` applies
to OS commands and does not bypass Burp approval. Read-only sessions permit only
an explicit set of history/issue/config reads and encoders; they refuse request
sending and state changes. The extension may impose its own approvals as well.
Burp tool descriptions and results are treated as untrusted evidence.

Burp and HYDRA must reach the same loopback endpoint. For HYDRA on a Linux server
and Burp on your workstation, forward the port over SSH. The client accepts HTTP
on loopback only and refuses a different-origin MCP message endpoint.

Tests exercise actual SSE initialization, tool listing and approved calls against
a local MCP fixture, plus denied calls, argument validation and read-only checks.
This is protocol verification; a live Burp GUI has not been tested here.
