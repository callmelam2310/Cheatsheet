# Web Pentest Cheatsheet

> [!info] About
> Organized **by goal (vulnerability class), not by tool**. All sources merged; no per-project labels. From Compass/HackTricks catalog + ProjectDiscovery + reconFTW vuln checks. Updated 2026-09-29.

Testing a web app: recon & map → proxy setup → work each vulnerability class → review source → AI/LLM → payload/wordlist reference. Bulk automated scanners live in [[Recon Cheatsheet#6. Recon autoscan]] — noisy, always hand-verify.

## Contents
- [[#Recon & app mapping]]
- [[#Proxy & testing framework]]
- [[#Injection (SQL / NoSQL / command / SSTI)]]
- [[#XSS & client-side]]
- [[#Auth (JWT, OAuth, SAML, session)]]
- [[#Deserialization & Java/.NET]]
- [[#Request smuggling, cache & proxy abuse]]
- [[#SSRF, CORS, open redirect & takeover]]
- [[#API, GraphQL & WebSocket]]
- [[#Misc (race, ReDoS, prototype pollution, CSPT)]]
- [[#Source review & secrets]]
- [[#AI / LLM features]]
- [[#Payloads, wordlists & reference]]

---

## Recon & app mapping
*Fingerprint the stack, crawl, find hidden endpoints/params, read JS bundles.*

| Tool | Purpose |
|---|---|
| [`httpx`](https://github.com/projectdiscovery/httpx) | bulk host probe: status, title, tech, server. First step of any recon. |
| [`katana`](https://github.com/projectdiscovery/katana) | active crawler that parses JS for endpoints. Pair with gau for max coverage. |
| [`gau`](https://github.com/lc/gau) | historical URLs from Wayback/CommonCrawl/AlienVault; endpoints removed from the UI. |
| [`WhatWeb`](https://github.com/urbanadventurer/WhatWeb) | web tech fingerprint (richer plugin set than plain headers). |
| [`wafw00f`](https://github.com/EnableSecurity/wafw00f) | identify the WAF before firing payloads — decides if you need a bypass branch. |
| [`WhatWaf`](https://github.com/Ekultek/WhatWaf) | WAF detection plus matching tamper-script suggestions. |
| [`ffuf`](https://github.com/ffuf/ffuf) | fuzz dirs/files/params/vhosts. Fast, flexible filters (`-ac` auto-baseline). |
| [`feroxbuster`](https://github.com/epi052/feroxbuster) | recursive fuzz with link extraction; good for deep directory trees. |
| [`dirsearch`](https://github.com/maurosoria/dirsearch) | dir fuzz with solid built-in wordlists for a quick start. |
| [`Arjun`](https://github.com/s0md3v/Arjun) | hidden HTTP params (GET/POST/JSON) not present in the UI. |
| [`Param Miner`](https://github.com/PortSwigger/param-miner) | Burp extension; guesses headers/params outside the cache key. Essential for cache poisoning. |
| [`jsluice`](https://github.com/BishopFox/jsluice) | URLs/endpoints/secrets from JS via AST analysis (more accurate than regex). |
| [`LinkFinder`](https://github.com/panchocosil/burp-js-linkfinder-enhanced) | extract endpoints from JS bundles inside Burp. |
| [`OneListForAll`](https://github.com/six2dez/OneListForAll) | merged wordlist collection for web fuzzing. |
| [`leaky-paths`](https://github.com/ayoubfathi/leaky-paths) | wordlist of commonly leaked paths (config, backup, debug). |
| [`Auto_Wordlists`](https://github.com/carlospolop/Auto_Wordlists) | HackTricks wordlists split by purpose. |
| [`SecLists`](https://github.com/danielmiessler/SecLists) | industry-standard wordlist repo. Use the local copy — don't re-download. |
| [`nuclei`](https://github.com/projectdiscovery/nuclei) | CVE/misconfig/exposure templates. Run *after* reading the product's CVE notes. |
| [`bbot`](https://github.com/blacklanternsecurity/bbot) | recursive automated recon (subdomain → http → nuclei) for wide scope. |
| [`changedetection.io`](https://github.com/dgtlmoon/changedetection.io) | track page/endpoint changes over time; good for long engagements. |

## Proxy & testing framework
*Where most of the real work happens.*

| Tool | Purpose |
|---|---|
| [`Burp Suite Professional`](https://portswigger.net/burp) | main proxy: Scanner, Intruder, Repeater (HTTP/2), single-packet attack, Collaborator. |
| [`Turbo Intruder`](https://github.com/PortSwigger/turbo-intruder) | tens of thousands of req/s; required for race conditions (single-packet attack). |
| [`bambdas`](https://github.com/PortSwigger/bambdas) | Bambda scripts to filter/highlight proxy history in Burp. |
| [`interactsh`](https://github.com/projectdiscovery/interactsh) | OOB server (Collaborator alternative) — confirm blind SSRF/XXE/SQLi/RCE. |
| [`PyCript`](https://github.com/Anof-cyber/PyCript) | Burp extension for custom encrypt/decrypt of request bodies (apps that encrypt payloads). |
| [`wfuzz`](https://github.com/xmendez/wfuzz) | flexible fuzzing at any request position (header, cookie, body). |
| [`recollapse`](https://github.com/0xacb/recollapse) | generate input mutations (unicode, encoding) to find normalization flaws. |

## Injection (SQL / NoSQL / command / SSTI)

| Tool | Purpose |
|---|---|
| [`sqlmap`](https://github.com/sqlmapproject/sqlmap) | automated SQLi exploitation. Run only *after* confirming a manual signal. |
| [`NoSQLi (Charlie-belmer)`](https://github.com/Charlie-belmer/nosqli) | scan/exploit NoSQL injection. |
| [`NoSQL-Attack-Suite`](https://github.com/C4l1b4n/NoSQL-Attack-Suite) | payloads + scripts for attacking MongoDB. |
| [`nosqlinjection_wordlists`](https://github.com/cr0hn/nosqlinjection_wordlists) | wordlists specific to NoSQLi. |
| [`tplmap`](https://github.com/epinna/tplmap) | automated SSTI detect & exploit (many engines). |
| [`SSTImap`](https://github.com/vladko312/sstimap) | tplmap successor, supports newer engines. |
| [`TInjA`](https://github.com/Hackmanit/TInjA) | template injection scanner, server-side and client-side. |
| [`template-injection-table`](https://github.com/Hackmanit/template-injection-table) | payload syntax lookup per template engine. |
| [`Fenjing`](https://github.com/Marven11/Fenjing) | auto-generate Jinja2 payloads that bypass WAF/blacklist. |
| [`Gopherus`](https://github.com/tarunkant/Gopherus) | build `gopher://` payloads for SSRF → Redis/MySQL/FastCGI/SMTP. |
| [`odat`](https://github.com/quentinhardy/odat) | Oracle Database Attacking Tool — deep Oracle exploitation. |

## XSS & client-side

| Tool | Purpose |
|---|---|
| [`DOM Invader`](https://portswigger.net/burp/documentation/desktop/tools/dom-invader) | built into Burp Browser; auto-traces source→sink for DOM XSS and prototype pollution. |
| [`domloggerpp`](https://github.com/kevin-mizu/domloggerpp) | browser extension logging every DOM sink access — catches what DOM Invader misses. |
| [`eval-villain`](https://github.com/doyensec/eval-villain) | hooks eval/Function/innerHTML and prints the input reaching them. |
| [`JSONBee`](https://github.com/zigoo0/JSONBee) | ready JSONP endpoints — bypass CSP via allowlisted domains. |
| [`CSP Evaluator`](https://csp-evaluator.withgoogle.com/) | scores a CSP and points out bypass directions. |
| [`postMessage-tracker`](https://github.com/fransr/postMessage-tracker) | Chrome extension logging postMessage handlers — find listeners missing origin checks. |
| [`posta`](https://github.com/benso-io/posta) | dedicated cross-window postMessage testing tool. |
| [`XSSChallengeWiki`](https://github.com/cure53/XSSChallengeWiki) | XSS challenge collection — practice context and bypasses. |
| [`HTTPLeaks`](https://github.com/cure53/HTTPLeaks) | enumerate every way HTML can emit a request — scriptless exfil. |
| [`xsinator`](https://xsinator.com/) | XS-Leaks test suite by technique. |

## Auth (JWT, OAuth, SAML, session)

| Tool | Purpose |
|---|---|
| [`jwt_tool`](https://github.com/ticarpi/jwt_tool) | analyze/modify/re-sign JWTs; test alg:none, kid injection, jku/x5u, HS/RS confusion. |
| [`JWT Editor`](https://github.com/PortSwigger/jwt-editor) | Burp extension for JWTs — edit claims and re-sign in Repeater. |
| [`hashcat`](https://hashcat.net/hashcat/) | crack JWT HS256 secrets (`-m 16500`), password hashes, PINs. |
| [`badsecrets`](https://github.com/blacklanternsecurity/badsecrets) | detect default/weak framework secrets (ViewState, Rails, Django, Express). |
| [`Blacklist3r`](https://github.com/NotSoSecure/Blacklist3r) | find known .NET MachineKeys to forge ViewState. |
| [`SAMLExtractor`](https://github.com/fadyosman/SAMLExtractor) | extract and analyze SAMLResponse from traffic. |
| [`SAML Raider`](https://github.com/CompassSecurity/SAMLRaider) | Burp extension for XSW and SAML assertion editing. |
| [`cookie-monster`](https://github.com/DigitalInterruption/cookie-monster) | brute Express/Node cookie signing secrets. |
| [`flask-unsign`](https://github.com/Paradoxis/Flask-Unsign) | decode/brute/re-sign Flask session cookies. |
| [`fireprox`](https://github.com/ustayready/fireprox) | one-off AWS API Gateway endpoint → one IP per request, bypass IP-based rate limits. |
| [`IP Rotate`](https://github.com/PortSwigger/ip-rotate) | Burp extension rotating source IP via API Gateway. |
| [`hashtag-fuzz`](https://github.com/Hashtag-AMIN/hashtag-fuzz) | randomized-header fuzzing + proxy rotation to dodge throttling. |

## Deserialization & Java/.NET

| Tool | Purpose |
|---|---|
| [`ysoserial`](https://github.com/frohoff/ysoserial) | Java gadget chains (CommonsCollections, Spring, ROME…). |
| [`ysoserial.net`](https://github.com/pwntester/ysoserial.net) | .NET version — ViewState, BinaryFormatter, Json.NET. |
| [`ysonet`](https://github.com/irsdl/ysonet) | maintained ysoserial.net fork with new gadgets. |
| [`phpggc`](https://github.com/ambionics/phpggc) | PHP gadget chains (Laravel, Monolog, Symfony…). Run in Kali WSL — Windows AV blocks it. |
| [`marshalsec`](https://github.com/mbechler/marshalsec) | JNDI/deserialization gadgets, spins up LDAP/RMI servers. |
| [`JNDI-Exploit-Kit`](https://github.com/pimps/JNDI-Exploit-Kit) | JNDI server for log4shell-style exploits. |
| [`GadgetProbe`](https://github.com/BishopFox/GadgetProbe) | probe classes on the target classpath via blind deserialization. |
| [`laravel-crypto-killer`](https://github.com/synacktiv/laravel-crypto-killer) | exploit a leaked Laravel APP_KEY → forge cookies / decrypt payloads. |
| [`php_filter_chain_generator`](https://github.com/synacktiv/php_filter_chain_generator) | build `php://filter` chains to turn LFI into RCE without upload. |
| [`dnSpy`](https://github.com/dnSpy/dnSpy) | decompile + debug .NET assemblies. |

## Request smuggling, cache & proxy abuse

| Tool | Purpose |
|---|---|
| [`HTTP Request Smuggler`](https://github.com/PortSwigger/http-request-smuggler) | Burp extension to detect/exploit desync (CL.TE/TE.CL/H2). Safest way to test. |
| [`smuggler`](https://github.com/defparam/smuggler) | standalone desync detection script (no Burp). |
| [`smugglefuzz`](https://github.com/Moopinger/smugglefuzz) | next-gen desync fuzzer, HTTP/2 focused. |
| [`t-reqs`](https://github.com/bahruzjabiyev/t-reqs-http-fuzzer) | HTTP fuzzer building malformed requests to find parser differentials. |
| [`websocket-smuggle`](https://github.com/0ang3el/websocket-smuggle) | WebSocket tunneling techniques to bypass proxies. |
| [`byp4xx`](https://github.com/lobuhi/byp4xx) | auto-try the full set of 403/401 bypass techniques. |
| [`fuzzhttpbypass`](https://github.com/carlospolop/fuzzhttpbypass) | fuzz header/method/path to bypass 403 (HackTricks author). |
| [`gixy`](https://github.com/dvershinin/gixy) | static analysis of nginx config — catches alias traversal, off-by-slash. |
| [`humble`](https://github.com/rfc-st/humble) | scores a response's security headers. |

## SSRF, CORS, open redirect & takeover

| Tool | Purpose |
|---|---|
| [`ssrf-sheriff`](https://github.com/teknogeek/ssrf-sheriff) | SSRF callback server, returns custom content per Content-Type. |
| [`Singularity of Origin`](https://github.com/nccgroup/singularity) | complete DNS rebinding framework. |
| [`DNSrebinder`](https://github.com/mogwailabs/DNSrebinder) | minimal DNS rebinding server. |
| [`Corsy`](https://github.com/s0md3v/Corsy) | bulk CORS misconfiguration scanner. |
| [`CORScanner`](https://github.com/chenjj/CORScanner) | CORS scanner supporting many origin variants. |
| [`OpenRedireX`](https://github.com/devanshbatham/OpenRedireX) | open-redirect fuzzer with built-in bypass payloads. |
| [`Oralyzer`](https://github.com/0xNanda/Oralyzer) | open-redirect analysis + checks chaining to SSRF. |
| [`can-i-take-over-xyz`](https://github.com/EdOverflow/can-i-take-over-xyz) | reference table of takeover-prone services and their signatures. |
| [`dnsReaper`](https://github.com/punk-security/dnsReaper) | fast subdomain-takeover scanner, many signatures. |
| [`Subdominator`](https://github.com/Stratus-Security/Subdominator) | takeover detection with few false positives. |
| [`hakoriginfinder`](https://github.com/hakluke/hakoriginfinder) | find the origin IP behind a CDN by comparing responses. |
| [`fav-up`](https://github.com/pielco11/fav-up) | find the real IP via favicon hash on Shodan. |

## API, GraphQL & WebSocket

| Tool | Purpose |
|---|---|
| [`InQL`](https://github.com/doyensec/inql) | Burp extension for GraphQL — introspection, query generation, schema attacks. |
| [`graphw00f`](https://github.com/dolevf/graphw00f) | fingerprint the GraphQL engine (Apollo, Hasura…) to pick the right technique. |
| [`graphql-cop`](https://github.com/dolevf/graphql-cop) | quick GraphQL config audit (introspection, batching, field suggestion). |
| [`clairvoyance`](https://github.com/nikitastupin/clairvoyance) | rebuild the schema when introspection is off, using error hints. |
| [`GraphQLmap`](https://github.com/swisskyrepo/GraphQLmap) | interact with and exploit GraphQL endpoints. |
| [`batchql`](https://github.com/assetnote/batchql) | test batching/alias abuse to bypass rate limits. |
| [`graphql-threat-matrix`](https://github.com/nicholasaleks/graphql-threat-matrix) | defense comparison per GraphQL implementation. |
| [`sj (Swagger Jacker)`](https://github.com/BishopFox/sj) | find and exploit exposed Swagger/OpenAPI docs. |
| [`kiterunner`](https://github.com/assetnote/kiterunner) | brute API routes with schema-style wordlists (better than dirbuster for APIs). |
| [`STEWS`](https://github.com/PalindromeLabs/STEWS) | WebSocket testing toolkit (discovery, fingerprint, vuln). |
| [`WebSocketTurboIntruder`](https://github.com/d0ge/WebSocketTurboIntruder) | high-speed WebSocket message fuzz/flood in Burp. |
| [`grpc-pentest-suite`](https://github.com/nxenon/grpc-pentest-suite) | gRPC/gRPC-web testing (decode protobuf, edit messages). |

## Misc (race, ReDoS, prototype pollution, CSPT)

| Tool | Purpose |
|---|---|
| [`regexploit`](https://github.com/doyensec/regexploit) | find ReDoS-prone regexes in source/JS. |
| [`redos-detector`](https://github.com/tjenkinson/redos-detector) | check whether a regex is safe, with an explanation. |
| [`vuln-regex-detector`](https://github.com/davisjam/vuln-regex-detector) | detect dangerous regexes across many languages. |
| [`ppmap`](https://github.com/kleiton0x00/ppmap) | client-side prototype pollution scanner + gadget finder. |
| [`ppfuzz`](https://github.com/dwisiswant0/ppfuzz) | fast prototype-pollution fuzzer (Rust). |
| [`proto-find`](https://github.com/kosmosec/proto-find) | find pollution points via URL/params. |
| [`server-side-prototype-pollution`](https://github.com/KTH-LangSec/server-side-prototype-pollution) | SSPP research + detection techniques (with gadgets). |
| [`CSPTBurpExtension`](https://github.com/doyensec/CSPTBurpExtension) | Burp extension detecting Client-Side Path Traversal. |
| [`XSRFProbe`](https://github.com/0xInfection/XSRFProbe) | automated CSRF audit, generates PoC. |

## Source review & secrets

| Tool | Purpose |
|---|---|
| [`semgrep`](https://github.com/returntocorp/semgrep) | AST-pattern SAST — fewer false positives than grep, ready rulesets (p/java, p/secrets). |
| [`CodeQL`](https://github.com/github/codeql-action) | dataflow queries over code — proves source→sink instead of guessing. |
| [`nodejsscan`](https://github.com/ajinabraham/nodejsscan) | SAST for Node.js. |
| [`insider`](https://github.com/insidersec/insider) | multi-language SAST, fast in CI. |
| [`electronegativity`](https://github.com/doyensec/electronegativity) | audit Electron apps (nodeIntegration, contextIsolation…). |
| [`git-dumper`](https://github.com/arthaud/git-dumper) | download a whole repo when /.git/ is exposed. |
| [`GitDump`](https://github.com/Ebryx/GitDump) | dump .git even with directory listing off. |
| [`gitrob / git-vuln-finder`](https://github.com/michenriksen/gitrob) | find secrets in commit history. |
| [`trufflehog`](https://github.com/trufflesecurity/trufflehog) | entropy + hundreds of detectors, verifies keys are live. |
| [`webcrack / wakaru / humanify`](https://github.com/j4k0xb/webcrack) | de-minify/unbundle JS back to readable code (humanify uses an LLM). |
| [`shuji`](https://github.com/paazmaya/shuji) | reverse a webpack bundle back to original modules. |

## AI / LLM features
*Test embedded AI features — prompt injection, guardrails, tool abuse.*

| Tool | Purpose |
|---|---|
| [`garak`](https://github.com/NVIDIA/garak) | NVIDIA's LLM vuln scanner — dozens of jailbreak/leak/toxicity probes. |
| [`promptmap`](https://github.com/utkusen/promptmap) | automatically test prompt injection on your LLM app. |
| [`PyRIT`](https://github.com/Azure/PyRIT) | Microsoft's AI red-team framework — build iterative attack scenarios. |
| [`Adversarial Robustness Toolbox`](https://github.com/Trusted-AI/adversarial-robustness-toolbox) | ML attack/defense suite (evasion, poisoning, extraction). |
| [`Burp AI / MCP`](https://portswigger.net/burp/documentation/desktop/extensions) | connect Burp to an AI agent for traffic analysis. |

## Payloads, wordlists & reference

| Tool | Purpose |
|---|---|
| [`PayloadsAllTheThings`](https://github.com/swisskyrepo/PayloadsAllTheThings) | payloads by vuln class. Local copy in the KB — grep offline. |
| [`HackTricks`](https://github.com/HackTricks-wiki/hacktricks) | technique wiki. Local copy (web + mobile + AI) since the online site blocks bots. |
| [`OWASP MASTG / MASVS`](https://github.com/OWASP/owasp-mastg) | mobile testing standard — 112 MASTG-TESTs rendered in the KB. |
| [`OWASP WSTG`](https://github.com/OWASP/wstg) | web testing standard — 112 tests, local copy in the KB. |
| [`vulhub`](https://github.com/vulhub/vulhub) | Docker labs reproducing CVEs — spin up an environment to safely confirm an exploit. |
| [`exploit-db / searchsploit`](https://www.exploit-db.com/) | look up public exploits by product + version. |

---
See also: [[README]] · [[Recon Cheatsheet]]
