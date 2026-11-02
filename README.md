# browser-mcp

A browser-driven MCP server that gives Claude a full Chromium plus **323 tools** for web pentesting, OSINT, content extraction, Perplexity-style search, and automation. One tool call can drive a page, scan it for vulns, pull backend source, generate a Tampermonkey script, or spin up 8 parallel sub-agents to hit a target from every angle at once.

Everything works on authorized targets — your own sites, bug-bounty programs, CTFs, pentest engagements.

---

## Install

```bash
git clone <this repo>
cd browser-mcp
npm install
npx playwright install chromium
npm run build
npm link   # exposes `browser-mcp` on your PATH
```

## Add to Claude Code

```bash
claude mcp add browser-mcp -- browser-mcp
```

Or edit your MCP config:
```json
{ "mcpServers": { "browser-mcp": { "command": "browser-mcp", "args": [] } } }
```

Then tell Claude: _"my browser-mcp is running"_ and all 323 tools are available.

## CLI checks
```
browser-mcp --help
browser-mcp --list-tools   # prints every tool and its one-line description
browser-mcp --version
```

---

## Tool index

| Group | Prefix | Count | Covers |
|---|---|---|---|
| [Browser control](#browser-control) | `browser_` | 23 | open/close sessions, navigate, click, type, screenshot, cookies, headers |
| [Advanced browser](#advanced-browser) | `browser_` | 15 | device emulation, geo, perms, PDF, downloads, tabs, metrics |
| [Browser interaction](#browser-interaction) | `browser_` | 24 | hover, drag, double-click, fill_form, click_by_text, waits |
| [Live view](#live-view) | `liveview_` | 3 | watch the browser in your own browser via MJPEG + click-forward |
| [Console](#console) | `console_` | 5 | paste JS, capture logs/dialogs, inject scripts, init-scripts |
| [Source viewing](#source-viewing) | `source_` | 8 | list scripts/styles, fetch, grep everything, DOM outline, find by text/attr |
| [Discovery](#discovery) | `site_profile`, `crawl_site`, `deep_scan` | 3 | one-shot full site profiling + crawl + aggregate scan |
| [API / routes](#api--routes) | `api_`, `routes_`, `chunks_` | 8 | chunk discovery, API extraction, frontend route maps, auth testing |
| [Network](#network) | `network_` | 8 | capture, replay, fuzz, HAR export |
| [Vulnerability scanners](#vulnerability-scanners) | `scan_` | 26 | headers, XSS, SQLi, SSRF, SSTI, LFI, CRLF, CORS, JWT, prototype pollution, more |
| [Backend source extraction](#backend-source-extraction) | `exploit_` | 9 | LFI → source dump, git dump, sourcemap → TypeScript, Actuator secrets |
| [Reconnaissance](#reconnaissance) | `recon_` | 16 | DNS, subdomains (brute + crt.sh + wayback), TLS, WAF, CMS, favicon hash, ports, banners |
| [Cookies + JWT](#cookies--jwt) | `cookie_`, `jwt_` | 10 | parse, generate, build JWTs, crack HMAC secrets |
| [Username enumeration](#username-enumeration) | `username_` | 3 | profile endpoint, batch check, wordlist generators |
| [WebSocket](#websocket) | `ws_` | 8 | active client, passive capture, replay frames |
| [Crypto + codecs](#crypto--codecs) | `codec_`, `crypto_`, `hash_`, `password_` | 8 | base64/hex/url/entities, XOR, rot, AES, hash ID + crack, password strength |
| [Userscripts (Tampermonkey)](#userscripts-tampermonkey) | `userscript_` | 2 | build full .user.js, convert console snippet to userscript |
| [Reporting](#reporting) | `findings_`, `report_` | 6 | accumulator + markdown/JSON report |
| [Swarm / sub-agents](#swarm--sub-agents) | `swarm_`, `sub_agent_` | 8 | 8+ parallel workers, each in its own browser session |
| [Search (Perplexity-style)](#search) | `search_` | 15 | web, news, images, GitHub, Reddit, Wikipedia, arXiv, SO, HN, YouTube, cited answers |
| [Content extraction](#content-extraction) | `extract_` | 15 | Readability article, OG/meta/JSON-LD, RSS/Atom, Wayback, tables, emails/phones/handles |
| [Text intelligence](#text-intelligence) | `ai_` | 13 | summarize, keywords, sentiment, language detect, readability, outline, diff |
| [Data wrangling](#data-wrangling) | `data_` | 15 | JSON path/pretty/keys, CSV↔JSON, XML, YAML, group-by, filter, URL parse |
| [OSINT](#osint) | `osint_` | 16 | username sweep across 25+ sites, email guess, HIBP k-anon, Discord/Roblox/phone, WHOIS, Gravatar |
| [Dev utilities](#dev-utilities) | `dev_` | 15 | regex test/explain, cron parse, color convert, UUID, slugify, lorem, QR, SQL format |
| [Payload bank](#payload-bank-from-github-raws) | `payloads_` | 6 | 19 named payload sets (SecLists / PayloadsAllTheThings / payloadbox) with offline fallbacks |
| [WAF bypass + CVE probes](#waf-bypass--cve-probes) | `bypass_`, `cve_`, `template_` | 22 | double-URL, hex SQL, homoglyph, Log4Shell, Spring4Shell, Shellshock, Struts, Tomcat default creds |
| [Low-level](#low-level) | `http_request`, `base64`, `url_codec`, `hash` | 4 | raw HTTP through session, basic codecs |

---

## Browser control

| Tool | What it does |
|---|---|
| `browser_open` | New session. Opts: `headless` (default true — set false for a visible window), `recordVideoDir` (save .webm on close), `userAgent`, viewport, proxy, extraHeaders. Returns `sessionId`. |
| `browser_list_sessions` / `browser_close` | List / close sessions. |
| `browser_navigate` | Go to a URL. Opts: `waitUntil`, `timeoutMs`. |
| `browser_back` / `browser_forward` / `browser_reload` | History. |
| `browser_screenshot` | PNG of the viewport (what the browser shows, not the OS screen). Opts: `fullPage`, `selector` (element only), `clip`, `omitBackground`. |
| `browser_get_html` / `browser_get_text` / `browser_get_url` | Current page. |
| `browser_click` / `browser_type` / `browser_press` / `browser_select` | Basic interactions. |
| `browser_wait_for` | Wait for selector / URL / load state. |
| `browser_evaluate` | Run arbitrary JS inside the page. |
| `browser_cookies_get` / `browser_cookies_set` / `browser_cookies_clear` | Cookie jar. |
| `browser_set_headers` / `browser_set_user_agent` | Extra HTTP headers for future requests. |
| `browser_dom_query` | Query selector → tag + text + attrs + outerHTML. |

**Example** — open a session, navigate, screenshot:
```
browser_open {} → { sessionId: "ab12" }
browser_navigate { url: "https://example.com" }
browser_screenshot {}
```

## Advanced browser

| Tool | What it does |
|---|---|
| `browser_emulate_device` | iPhone 14 / Pixel 7 / iPad / desktop presets. Sets UA + viewport + DPR + touch. |
| `browser_set_geolocation` / `browser_set_timezone` / `browser_set_locale` | Spoof location, TZ, Accept-Language. |
| `browser_grant_permissions` | Grant camera, mic, notifications, clipboard, geolocation, etc. |
| `browser_new_tab` / `browser_list_tabs` / `browser_switch_tab` / `browser_close_tab` | Multi-tab. |
| `browser_pdf` | Save page as PDF (Chromium only). |
| `browser_download` | Download a file through the session's cookies. |
| `browser_upload_file` | Set files on `<input type=file>`. |
| `browser_accessibility_tree` | ARIA snapshot — what screen readers see. |
| `browser_metrics` | TTFB, FP, FCP, DOMContentLoaded, memory. |
| `browser_mouse` / `browser_scroll` | Low-level input. |

## Browser interaction

| Tool | What it does |
|---|---|
| `browser_hover` | Trigger CSS `:hover` + `onmouseover`. |
| `browser_double_click` / `browser_right_click` / `browser_focus` | Specialized clicks + focus-without-click. |
| `browser_drag` | Drag-and-drop. |
| `browser_type_slow` | Per-char delayed typing (anti-bot). |
| `browser_fill_form` | Fill many fields in one call — text/select/radio/checkbox. |
| `browser_submit_form` | Submit by selector. |
| `browser_check` / `browser_uncheck` | Checkboxes. |
| `browser_click_by_text` | Click by visible text, no selector needed. |
| `browser_find_by_text` | Locate by visible text → tag + href + bbox + ARIA. |
| `browser_links` | List every `<a href>` with text + resolved href. |
| `browser_follow_link` | Click a link by its text. |
| `browser_zoom` / `browser_viewport_set` / `browser_set_offline` | Page settings. |
| `browser_dialog_handler` | Pre-arm accept/dismiss/accept-with-text for alert/confirm/prompt. |
| `browser_history_go` | Jump N entries forward or back. |
| `browser_wait_for_response` | Wait for XHR matching URL regex, return status + body. |
| `browser_wait_for_url` | Wait until URL matches. |
| `browser_wait_idle` | Wait for `networkidle`. |
| `browser_bring_to_front` | Pop headful window. |
| `browser_record_start` | Open a session with `.webm` video recording. |
| `browser_cdp_endpoint` | Return the raw CDP WebSocket URL. |

**Example** — fill a login form by text:
```
browser_fill_form {
  fields: { 'input[name="user"]': "alice", 'input[name="pw"]': "p@ss" },
  submitSelector: "#login-btn"
}
```

## Live view

Watch the headless browser in your own browser in real time.

| Tool | What it does |
|---|---|
| `liveview_start` | Starts a local HTTP server. Returns a URL — open it in Chrome/Firefox/Safari and you'll see the Playwright page at ~10 fps MJPEG with the current URL in a top bar. Clicks on the stream forward to the headless browser. |
| `liveview_stop` | Kill the live-view server. |
| `liveview_status` | List running live-views. |

## Console

| Tool | What it does |
|---|---|
| `console_eval` | Paste JS, get the return value + any `console.log` it emitted. Expression or async block. |
| `console_get_logs` | Captured `console.log/warn/error`, `pageerror`, dialogs. Filter by type/pattern. |
| `console_clear_logs` | Clear the buffer. |
| `console_inject_script` | Drop a `<script>` tag with the given code. |
| `console_prepend_init_script` | Run code BEFORE any page JS boots (for monkey-patching SPAs). |

## Source viewing

| Tool | What it does |
|---|---|
| `source_list_scripts` | Every `<script>` — src, inline length, async/defer/module. |
| `source_list_stylesheets` | Linked + inline styles. |
| `source_fetch` | Fetch any URL through the session (cookies tagged). |
| `source_search` | Regex-grep across the page HTML + every captured response body. |
| `source_dom_outline` | Compact DOM tree down to a depth. |
| `source_find_element` | Find by text/attr/role → tag + attrs + bbox. |
| `source_storage_dump` | localStorage + sessionStorage + IndexedDB names. |
| `source_storage_set` | Write to local/session storage. |

## Discovery

| Tool | What it does |
|---|---|
| `site_profile` | Pulls the HTML first, parses every linked resource, fetches them, indexes everything (URLs, emails, comments, PHP/Python/Ruby/.NET tech markers, cookie-derived framework hints). Works on any backend. |
| `crawl_site` | Breadth-first same-origin crawl, every page body goes into the capture. |
| `deep_scan` | One-shot: profile → crawl → headers → outdated → secrets → sensitive files → API extraction → routes. Aggregated findings. |

## API / routes

| Tool | What it does |
|---|---|
| `chunks_discover` | Resolve every JS chunk the page loads — webpack chunk URLs, Next.js `__BUILD_MANIFEST`, Vite modulepreload, dynamic imports, sourcemap hints. Downloads them all so later greps see them. |
| `api_from_network` | Group captured XHR/fetch by endpoint — methods, status codes, content types, sample bodies. |
| `api_from_source` | Grep every captured JS for fetch/axios/XHR call sites + URL templates. |
| `api_graphql_introspect` | Send a GraphQL introspection query. |
| `api_openapi_discover` | Probe 15+ Swagger/OpenAPI locations. |
| `routes_frontend_discover` | React Router / Next build manifest / Vue Router / path-prop routes from bundles. |
| `routes_backend_probe` | Hit a candidate list, flag responses with session markers (`"email":`, `logged in as`, `admin panel`). |
| `routes_test_auth` | Hit each route twice — authed + anonymous — flag identical responses as IDOR candidates. |

## Network

| Tool | What it does |
|---|---|
| `network_start_recording` / `network_stop_recording` / `network_clear` | Capture control. |
| `network_list_requests` | Filter by url regex, method, status, resource type. |
| `network_get_request` | Full detail by id. |
| `network_replay_request` | Replay with overrides (url, method, headers, body, query). |
| `network_fuzz_param` | Replay a request many times with a param iterated through a payload list — concurrent, baseline-diff. |
| `network_curl` | Export a captured request as a curl command. |
| `network_har_export` | HAR 1.2 archive. |

## Vulnerability scanners

| Tool | What it does |
|---|---|
| `scan_headers` | OWASP security-header checklist + CSP unsafe-inline/wildcard detection. |
| `scan_cookies` | Secure / HttpOnly / SameSite flags. |
| `scan_cors` | Origin reflection + ACAO=null + credentials=true confusion. |
| `scan_xss_reflected` | Context-aware XSS probe (script / attribute / HTML). |
| `scan_sqli` | Error + boolean + time-based SQLi. |
| `scan_open_redirect` | 5 common bypass payloads. |
| `scan_mixed_content` | HTTPS page loading HTTP subresources. |
| `scan_clickjacking` | Missing X-Frame-Options / CSP frame-ancestors. |
| `scan_jwt_decode` | Decode + flag alg=none, missing exp, expired. |
| `scan_tech_fingerprint` | Server + framework + lib version detection. |
| `scan_directory` | 25+ common paths probe. |
| `scan_robots_sitemap` | Parse robots.txt + sitemap.xml. |
| `scan_forms` | Form inventory + CSRF-token heuristic + non-HTTPS password posting. |
| `scan_links` | Internal/external link extraction. |
| `scan_subdomain_takeover` | 6 dangling-DNS fingerprints (GH Pages, S3, Heroku, Azure, Fastly, CloudFront). |
| `scan_full` | Runs headers + cookies + forms + mixed + tech + clickjacking + robots on current page. |
| `scan_outdated` | PHP/Apache/nginx/jQuery/Angular/WordPress/Lodash/Node version detection vs CVE table. |
| `scan_api_keys` | 60+ vendor patterns (AWS/Google/Stripe/GitHub/Anthropic/OpenAI/Slack/Discord/etc.) + context + entropy sweep, scans ALL captured sources + DOM + storage. |
| `scan_js_secrets` | Alias for `scan_api_keys`. |
| `scan_sensitive_files` | 69-path probe (VCS leaks, env, backups, admin consoles) with content confirmation. |
| `scan_backup_variants` | For a URL, try `.bak`, `~`, `.old`, `.zip` etc. |
| `scan_methods` | Which HTTP methods accepted; flag PUT/DELETE/TRACE/PATCH <400. |
| `scan_rate_limit` | Parallel-fire N requests, report 429 / RateLimit headers. |
| `scan_ssti` | 8-engine SSTI probe (Jinja2/Twig/Mako/Handlebars/ERB/Smarty/FreeMarker/Velocity). |
| `scan_lfi` | 9 traversal variants, detects passwd/win.ini/php-filter base64. |
| `scan_cmdi_time` | Time-based command injection (sleep, ping). |
| `scan_crlf` | CRLF header injection via percent-encoded + UTF-8 variants. |
| `scan_host_header` | Host / X-Forwarded-Host injection. |
| `scan_prototype_pollution` | `__proto__[x]` + `constructor.prototype` tests. |
| `scan_nosql_injection` | MongoDB `$ne` / `$gt` / `$regex` operators. |
| `scan_dom_xss` | Canary via location.hash/search → check DOM sinks. |
| `scan_ssrf` | Localhost / 169.254.169.254 / file:// / gopher:// / optional OOB. |
| `scan_cache_poison` | X-Forwarded-Host persistence into cache. |

## Backend source extraction

Once you've confirmed a vuln, pull the actual code.

| Tool | What it does |
|---|---|
| `exploit_lfi_dump_sources` | Given a working LFI param, iterate 50+ app-source paths (PHP/Laravel/Rails/Django/Node/Spring/.NET). Supports `usePhpFilter` for `php://filter/convert.base64-encode` wrapping, auto-decoded. |
| `exploit_sourcemap_dump` | Fetch every `.js.map`, extract `sourcesContent` → original TypeScript/JSX. |
| `exploit_git_dump` | If `/.git` exposed, pull HEAD/config/refs, parse binary `.git/index`, zlib-decompress loose objects. |
| `exploit_svn_dump` | Probe `.svn/entries`, `wc.db`, `pristine/`. |
| `exploit_env_from_actuator` | Spring Boot — hit 15 Actuator endpoints, extract secrets from `/actuator/env`. |
| `exploit_debug_panels` | 15 framework debug-panel probes — Laravel Ignition, Rails info, Django debug, Flask Werkzeug, Spring, ASP.NET elmah, Symfony profiler. |
| `exploit_sources_backup` | For each source file, try 13 backup variants. |
| `exploit_wordpress` | wp-config variants, debug.log, REST user enum, xmlrpc, readme version. |
| `exploit_phpinfo_parse` | Parse phpinfo output — DOCUMENT_ROOT, open_basedir, disable_functions, allow_url_include, PHP version. |

## Reconnaissance

| Tool | What it does |
|---|---|
| `recon_dns` | A/AAAA/MX/TXT/NS/CNAME/SOA/PTR. |
| `recon_subdomains_dns` | Brute with 70+ common prefixes. |
| `recon_subdomains_crtsh` | Certificate Transparency log pull — every subdomain ever seen in a cert. |
| `recon_subdomains_wayback` | Every subdomain Archive.org has ever seen. |
| `recon_tls` | Cert chain, SAN, protocol, cipher, expiry flagging. |
| `recon_tls_versions` | Probe TLS 1.0/1.1/1.2/1.3 support; flag insecure. |
| `recon_http_versions` | HTTP/1.1 / 2 / 3 (Alt-Svc) detection. |
| `recon_ports` | TCP scan on 40 common ports with banner grab. |
| `recon_banner_grab` | Raw TCP connect to host:port, capture banner. |
| `recon_waf` | 11 WAF/CDN fingerprints (Cloudflare, Akamai, AWS WAF, Imperva, F5, Sucuri, Fastly, ModSec, Wordfence, Barracuda, StackPath). |
| `recon_cms` | WordPress / Drupal / Joomla / Magento / Ghost / Shopify. |
| `recon_favicon_hash` | Shodan-style MMH3 hash → pivot query. |
| `recon_security_txt` | Parse `/.well-known/security.txt`. |
| `recon_dns_zone_transfer` | NS discovery + 53/tcp probe for AXFR. |
| `recon_asn_lookup` | IP → ASN / org via BGPView. |
| `recon_security_scorecard` | Aggregate 0-100 score (headers + TLS + software + exposed files) with A-F grade. |

## Cookies + JWT

| Tool | What it does |
|---|---|
| `cookie_list` / `cookie_set` / `cookie_delete` | Session cookie jar with filters. |
| `cookie_parse_set_cookie` | Set-Cookie header → structured record. |
| `cookie_header_from_jar` | `Cookie: a=b; c=d` request-header string. |
| `cookie_header_parse` | Reverse. |
| `cookie_generate` | Shapes: hex / uuid / base64url / numeric / laravel / phpsessid / flask / jwt-null. |
| `jwt_build` | HS256/384/512 or `alg=none`. |
| `jwt_verify_hs` | HMAC verify with a candidate secret. |
| `jwt_crack_hs` | Dictionary attack over HMAC secret. |

## Username enumeration

| Tool | What it does |
|---|---|
| `username_profile_endpoint` | Give it a URL template with `{username}` + 2-3 known-taken names → it probes known + random-unused samples, diffs status/length/markers, returns a classifier signature. Works on any site. |
| `username_check_batch` | Feeds a wordlist through the signature → `{available, taken, ambiguous, errors}`. |
| `username_wordlist` | Generators: `common`, `short`, `leet`, `numeric`, `mixed`. |

**Example** — guns.lol-style username checker:
```
username_profile_endpoint { urlTemplate: "https://guns.lol/{username}", knownTaken: ["alex","sam"] }
username_wordlist { shape: "common" }
username_check_batch { urlTemplate: ..., usernames: ..., signature: ... }
```

## WebSocket

| Tool | What it does |
|---|---|
| `ws_connect` / `ws_send` / `ws_messages` / `ws_close` / `ws_list` | Active WS client; captures frames. Can inherit session cookies. |
| `ws_capture_arm` / `ws_capture_dump` | Passive capture of every WS the page itself opens. |

## Crypto + codecs

| Tool | What it does |
|---|---|
| `codec_multi` | base64 / base64url / hex / url / url-double / html-entities / unicode-escape / utf-16-le. |
| `crypto_xor` | Repeating-key XOR. |
| `crypto_rot` | Caesar / rot13. |
| `crypto_aes` | AES-256-GCM encrypt/decrypt with scrypt KDF. |
| `hash_identify` | Guess algorithm by shape (bcrypt / argon2 / scrypt / MD5 / SHA-1/224/256/384/512 / NTLM / MySQL5). |
| `hash_crack_dict` | md5/sha1/sha256/sha512 dictionary attack. |
| `password_strength` | 0-4 score + reasons. |
| `password_in_top` | Top-100 check. |

## Userscripts (Tampermonkey)

| Tool | What it does |
|---|---|
| `userscript_build` | Build a complete .user.js from header spec + body. Full `@match` / `@grant` / `@run-at` / `@require` / `@connect` support. Optional `savePath`. |
| `userscript_from_console_eval` | Convert a working console snippet + target URL into a Tampermonkey-ready file in one call. |

**Example** — turn a devtools fix into a userscript:
```
userscript_from_console_eval {
  name: "Fix dark mode", targetUrls: ["https://example.com/*"],
  consoleSnippet: "document.body.classList.add('dark');"
}
```

## Reporting

| Tool | What it does |
|---|---|
| `findings_add` / `findings_add_bulk` / `findings_list` / `findings_clear` | Session-wide findings store. |
| `report_markdown` | Grouped-by-severity Markdown pentest report. Optional `savePath`. |
| `report_json` | Structured export. |

## Swarm / sub-agents

8 parallel workers per scan — each in its own isolated browser session.

| Tool | What it does |
|---|---|
| `swarm_scan` | Spawn N parallel workers (default 8). Named workers: `headers_cookies`, `outdated_software`, `api_keys`, `sensitive_files`, `injection_params`, `dom_and_pp`, `tech_waf_cms`, `sourcemaps`, `recon_dns_subs`, `debug_panels`, `methods_ratelimit`. Set `autoWait: true` to block until all finish. |
| `swarm_wait` | Wait for ids. |
| `swarm_pentest_report` | Markdown report grouped by severity with per-worker summary table. |
| `sub_agent_list` / `sub_agent_get` / `sub_agent_cancel` / `sub_agent_clear` | Lifecycle. |
| `sub_agent_spawn` | Arbitrary custom chain — pass `{name, steps:[{tool,args}]}` + optional `navigateTo` to run a pipeline in its own session, in parallel. |

## Search

Perplexity-style, no API keys.

| Tool | What it does |
|---|---|
| `search_web` | DuckDuckGo. |
| `search_bing` | Bing HTML. |
| `search_news` | Google News RSS. |
| `search_images` | DuckDuckGo (via vqd token). |
| `search_github_code` / `search_github_repos` | GitHub public API. |
| `search_reddit` | Reddit .json. |
| `search_wikipedia` + `wikipedia_summary` + `extract_wikipedia_page` | Full Wikipedia access. |
| `search_arxiv` | arXiv XML API. |
| `search_stackoverflow` | StackExchange API. |
| `search_hackernews` | Algolia. |
| `search_youtube` | ytInitialData scrape. |
| `search_with_citations` | **Perplexity-style — searches, fetches top N results, extracts each article's main text, returns a cited source list ready for the model to synthesize an answer.** |
| `search_followup` | Related-question generation. |

## Content extraction

| Tool | What it does |
|---|---|
| `extract_article` | Readability-style — picks `<article>`/`<main>` or highest-density div, strips scripts/styles/nav. |
| `extract_markdown` | HTML → Markdown. |
| `extract_meta` | Every meta tag, Open Graph, Twitter card, canonical, favicon, JSON-LD. |
| `extract_feed` | RSS 2.0 + Atom. |
| `extract_text_from_url` | Plain-text strip. |
| `extract_tables` | HTML tables → headers + rows. |
| `extract_links` | Every `<a>` with resolved href. |
| `extract_emails` / `extract_phones` / `extract_social_handles` | Twitter/GitHub/Insta/TikTok/LinkedIn/YouTube/Facebook/Mastodon. |
| `extract_wayback` / `extract_wayback_latest` | Archive.org snapshots. |
| `extract_opengraph_card` | Full share-card preview. |
| `extract_wikipedia_page` | Full page + sections list. |

## Text intelligence

Local — no external LLM needed.

| Tool | What it does |
|---|---|
| `ai_summarize` | Extractive — picks top-N sentences by TF. |
| `ai_keywords` | TF with stopword filtering. |
| `ai_sentences` | Smart sentence split. |
| `ai_reading_time` | words / wpm. |
| `ai_readability_flesch` | 0-100 + grade band. |
| `ai_sentiment` | Lexicon-based pos/neg. |
| `ai_detect_language` | CJK/Arabic/Hebrew/Cyrillic/Thai + 7 European via stopwords. |
| `ai_outline` | Headings from Markdown or HTML. |
| `ai_word_freq` / `ai_ngrams` | Frequency tables. |
| `ai_entities_simple` | Names/emails/urls/dates. |
| `ai_diff` | LCS line diff. |
| `ai_compare_urls` | Ingest multiple URLs → side-by-side keywords/length/time. |

## Data wrangling

| Tool | What it does |
|---|---|
| `data_json_pretty` / `data_json_minify` | Pretty / minify. |
| `data_json_path` | `$.a.b[0].c` selector. |
| `data_json_keys` | Deep list of every path. |
| `data_csv_to_json` / `data_json_to_csv` | Correctly quoted. |
| `data_url_parse` / `data_url_build` / `data_query_parse` | URL work. |
| `data_xml_to_json` / `data_yaml_to_json` | Parsers. |
| `data_table_to_markdown` | Pipe table. |
| `data_group_by` | count/sum/avg/min/max by key. |
| `data_sort` | by field asc/desc. |
| `data_filter` | JS expression per row. |

## OSINT

| Tool | What it does |
|---|---|
| `osint_username_sweep` | **Sherlock-style across 25+ sites** — GitHub, Twitter, Insta, TikTok, Reddit, YouTube, Medium, dev.to, Hashnode, GitLab, Bitbucket, Roblox, Steam, Twitch, Patreon, Spotify, SoundCloud, Pinterest, LinkedIn, Keybase, Product Hunt, HN, Goodreads, last.fm. |
| `osint_email_guess` | 13 common corporate email formats. |
| `osint_breach_patterns` | Local common-password + pattern check. |
| `osint_ip_lookup` | ip-api.com geolocation/ASN. |
| `osint_whois_rdap` | RDAP JSON. |
| `osint_shorten_unroll` | Chase redirect chain. |
| `osint_pastebin_search` | Dork paste sites. |
| `osint_github_user` | Public profile + emails leaked in commit metadata. |
| `osint_dns_history_crtsh` | Every SAN in CT logs. |
| `osint_robots_fingerprint` | Classify robots.txt. |
| `osint_hibp_pwned_prefix` | **HaveIBeenPwned k-anonymity** — only SHA-1 first-5 goes over the wire. |
| `osint_discord_lookup` | Snowflake → creation date + worker/proc. |
| `osint_roblox_user` | Username → id + description + avatar. |
| `osint_phone_meta` | Country code map (90+ countries). |
| `osint_hash_lookup_online` | hashes.com. |
| `osint_gravatar` | MD5 email → profile + avatar. |

## Dev utilities

| Tool | What it does |
|---|---|
| `dev_regex_test` / `dev_regex_explain` / `dev_regex_escape` | Regex work. |
| `dev_cron_describe` | English + next 5 UTC runs. |
| `dev_uuid` / `dev_nanoid` | ID generators. |
| `dev_timestamp` | Unix ↔ ISO. |
| `dev_base_convert` | 2/8/10/16/36. |
| `dev_color_convert` | hex ↔ rgb ↔ hsl. |
| `dev_slugify` | URL slug. |
| `dev_lorem` | Words / sentences / paragraphs. |
| `dev_random` | int / pick / shuffle / string. |
| `dev_sql_format` | Pretty-print SQL. |
| `dev_html_escape` | escape / unescape. |
| `dev_qrcode_text` | QR code image URL. |

## Payload bank (from GitHub raws)

19 curated payload sets, each with its GitHub raw URL + offline fallback.

| Set id | Source | What's in it |
|---|---|---|
| `xss-jhaddix` | SecLists `Fuzzing/XSS/XSS-Jhaddix.txt` | Jhaddix polyglots + classics |
| `xss-payloadallthethings` | PATT `XSS Injection/Intruders/xss-payload-list.txt` | Comprehensive XSS |
| `sqli-generic` | SecLists `Fuzzing/SQLi/Generic-SQLi.txt` | Generic SQLi |
| `sqli-authbypass` | payloadbox | Login bypass strings |
| `lfi-linux` | PATT `File Inclusion/Intruders/LFI-Jhaddix.txt` | Traversal + php://filter |
| `lfi-windows` | PATT | Windows paths |
| `ssti` | PATT | 8-engine SSTI fuzz |
| `ssrf` | PATT | Localhost + cloud metadata |
| `xxe` | payloadbox | XXE entity + DTD |
| `open-redirect` | payloadbox | Open-redirect bypasses |
| `cmdi` | payloadbox | Command injection |
| `nosqli-mongo` | PATT | Mongo operator payloads |
| `ldap` | PATT | LDAP filters |
| `wordlist-dir-common` / `-big` | SecLists `Discovery/Web-Content` | Directory wordlists |
| `passwords-top-1000` | SecLists | Top-1000 passwords |
| `usernames-top` | SecLists | Common usernames |
| `subdomains-top-5000` | SecLists DNS | Top-5000 subdomains |
| `user-agents` | SecLists | UA strings |

| Tool | What it does |
|---|---|
| `payloads_catalog` | List all 19 sets, URL, builtin size, cache status. |
| `payloads_get` | Fetch set by id (1h cache, offline fallback). |
| `payloads_from_raw_url` | Pull any one-per-line text URL. |
| `payloads_search` | Regex within a loaded set. |
| `payloads_apply` | **Fire the whole set at a URL param + baseline-diff + marker-hit + reflection detection.** |
| `payloads_pwn_methods` | Maps each category → payload set id + matching scanner — so Claude can auto-pick the right attack. |

## WAF bypass + CVE probes

**Encoding bypasses (14):**
`bypass_url_encode_double`, `bypass_url_encode_mixed`, `bypass_xss_case`, `bypass_xss_entity`, `bypass_xss_js_unicode`, `bypass_xss_fromcharcode`, `bypass_sql_hex` (`admin` → `0x61646d696e`), `bypass_sql_comment` (`UNION/**/SELECT`), `bypass_sql_concat` (CONCAT(CHAR(...))), `bypass_lfi_null_byte`, `bypass_lfi_traversal_variants` (17 forms), `bypass_cmd_ifs` (`${IFS}` tricks), `bypass_homoglyph` (Cyrillic lookalikes), `bypass_filename_double_ext` (`shell.php.jpg`, `.phtml`, `.phar`, `shell.php%00.jpg`, etc.).

**CVE-specific probes (6):**
- `cve_log4j_probe` — Log4Shell `${jndi:ldap://canary/x}` into query + 6 common headers
- `cve_spring4shell_probe` — Spring4Shell class.module.classLoader
- `cve_shellshock_probe` — CVE-2014-6271 via UA/Referer/Cookie
- `cve_struts_probe` — S2-045 OGNL in Content-Type
- `cve_tomcat_default_creds` — 8 common Manager combos
- `cve_phpmyadmin_default` — root/empty

**Templating (2):**
- `template_render` — Mustache-ish `{{var}}` substitution
- `template_combinations` — template × rows → list of filled strings

## Low-level

| Tool | What it does |
|---|---|
| `http_request` | Raw HTTP through the session (shares cookies). |
| `base64` | Encode/decode. |
| `url_codec` | URL encode/decode. |
| `hash` | md5/sha1/sha256/sha512. |

---

## Workflows

### 1. Full pentest of a target
```
browser_open {}
browser_navigate { url: "https://target.example" }
swarm_scan { url: "https://target.example", autoWait: true }
# 8 workers run in parallel in ~7-15 seconds
swarm_pentest_report { title: "Target assessment", target: "..." }
```

### 2. Perplexity-style cited search
```
search_with_citations { q: "latest Rust async runtimes 2026" }
# Returns 5 sources, each with full article text, ready to synthesize
```

### 3. Backend source extraction via LFI
```
scan_lfi { url: ".../page.php", param: "file" }
# confirms LFI works
exploit_lfi_dump_sources { url: ..., param: "file", usePhpFilter: true }
# dumps config.php, .env, etc. as base64, auto-decoded
```

### 4. Username availability on any site
```
username_profile_endpoint { urlTemplate: "https://guns.lol/{username}", knownTaken: ["admin","alex"] }
username_wordlist { shape: "short", length: 3 }
username_check_batch { urlTemplate: ..., signature: ..., usernames: ... }
```

### 5. Watch the browser live
```
browser_open {}
liveview_start {}
# → http://127.0.0.1:PORT/ — open in your browser, you see what the headless does
browser_navigate { url: "https://..." }
# the view updates in real time; click on it to drive the headless
```

### 6. Extract leaked API keys across all loaded sources
```
browser_navigate { url: "https://target" }
chunks_discover {}         # pulls every JS chunk
scan_api_keys {}           # 60+ patterns across every captured body + DOM + storage
```

### 7. Turn a working devtools fix into a userscript
```
# Open target in browser, test fix in devtools console until it works
userscript_from_console_eval {
  name: "Fix something",
  targetUrls: ["https://target/*"],
  consoleSnippet: "/* your working snippet */"
}
# → .user.js ready for Tampermonkey/Violentmonkey
```

### 8. Payload-set attack
```
payloads_pwn_methods {}
# Pick category → sqli, set → sqli-generic
payloads_apply {
  payloadId: "sqli-generic",
  url: "https://target/search",
  param: "q",
  successMarker: "sql syntax|mysql_error"
}
```

### 9. Multi-tab authenticated crawl
```
browser_open {}
# ... log in through the UI, cookies now in jar
cookie_header_from_jar {}   # grab Cookie: header for use elsewhere
browser_new_tab { url: "https://target/admin" }
crawl_site { depth: 2 }
```

### 10. Fingerprint everything about a host
```
site_profile {}
recon_tls { host: "..." }
recon_tls_versions { host: "..." }
recon_waf { url: "..." }
recon_cms { baseUrl: "..." }
recon_favicon_hash { baseUrl: "..." }
recon_security_scorecard { url: "..." }
```

---

## Troubleshooting

**Playwright can't find a browser** → `npx playwright install chromium`

**`browser-mcp` command not found** → `npm link` from the project dir, or run via full path: `node /path/to/browser-mcp/dist/index.js`.

**Headful mode not working** → You need a display server. `headless: false` only works where there's a visible desktop (not inside most cloud containers).

**crt.sh / Wayback / HIBP calls fail** → These need outbound HTTPS. If you're behind a strict proxy, they'll fail; the rest of the tools still work.

**Live-view page is blank** → Make sure your browser can reach `127.0.0.1:PORT`. In some containers that's blocked.

---

## Scope + ethics

Everything in here is for **authorized** security work — your own sites, bug-bounty programs, CTFs, pentest engagements. Don't point payload scanners at systems you don't have permission to test.
