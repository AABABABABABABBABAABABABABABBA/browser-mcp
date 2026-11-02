# browser-mcp

A browser-driven MCP server. Gives an LLM a real Chromium browser plus a toolbox for:

- navigating, clicking, typing, screenshotting
- pasting JS in the console and capturing what the page prints
- reading the page source, every script, every stylesheet, and grepping across all of it
- recording every network request and replaying any of them with overrides
- scanning for XSS / SQLi / open-redirect / weak JWTs / missing security headers / etc.
- building a Tampermonkey userscript from a snippet

67 tools in total.

## Install

```bash
git clone <this repo>
cd browser-mcp
npm install
npx playwright install chromium
npm run build
```

Then install it as a CLI on your PATH:

```bash
npm link
```

That gives you a `browser-mcp` command.

## Add it to Claude Code

```bash
claude mcp add browser-mcp -- browser-mcp
```

Or in your MCP config:

```json
{
  "mcpServers": {
    "browser-mcp": { "command": "browser-mcp", "args": [] }
  }
}
```

Then in Claude, just say "my browser-mcp is running" — Claude will see the tools.

## Quick checks

```bash
browser-mcp --help
browser-mcp --list-tools
browser-mcp --version
```

## Tool groups

| Group | Prefix | Examples |
|---|---|---|
| Browser | `browser_` | `browser_open`, `browser_navigate`, `browser_click`, `browser_screenshot`, `browser_cookies_set` |
| Console | `console_` | `console_eval`, `console_inject_script`, `console_get_logs`, `console_prepend_init_script` |
| Source  | `source_` | `source_list_scripts`, `source_fetch`, `source_search`, `source_dom_outline`, `source_find_element`, `source_storage_dump` |
| Network | `network_` | `network_list_requests`, `network_replay_request`, `network_fuzz_param`, `network_har_export`, `network_curl` |
| Scanners | `scan_` | `scan_headers`, `scan_xss_reflected`, `scan_sqli`, `scan_open_redirect`, `scan_jwt_decode`, `scan_cors`, `scan_full` |
| Userscript | `userscript_` | `userscript_build`, `userscript_from_console_eval` |
| Util | | `http_request`, `base64`, `url_codec`, `hash` |

Use for authorized pentesting / your own sites.
