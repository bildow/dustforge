# Show HN: DemiPass — Your AI agent uses your API keys without seeing them

Every AI coding assistant needs API keys. Right now you paste them into the chat, the .env file, or the prompt. They end up in logs, context windows, and potentially training data.

DemiPass stores your credentials and gives the agent a 30-second single-use token instead. The secret is injected server-side — into the HTTP header, the SSH command, wherever it needs to go. The agent gets the API response back. It never sees the key.

```
npm install demipass
```

It ships as MCP tools for Claude Code and Codex. The agent gets `demipass_ssh` (one call: ref code + host + command → output), `demipass_store` (deposit a secret), and 13 other tools. The tool descriptions teach the agent the protocol — no configuration beyond an initial token.

We use it ourselves. Our agents SSH into production servers, publish npm packages, and push code — all through DemiPass ref codes. No passwords in scripts, no tokens in config files.

It also includes a temporal alignment verifiability protocol — agents anchor decisions, handoffs, and audit events in a tamper-evident chain, so you can prove what happened and in what order across multiple agents.

Open source, MIT licensed. Two people, bootstrapped.

https://demipass.com | https://github.com/bildow/demipass
