# Recon Cheatsheet


Recon flows outside-in. OSINT and passive steps **never touch the target**; autoscan steps are **noisy — get approval and verify by hand** before calling anything a finding.

## Contents
- [[#0. Automation & orchestration]]
- [[#1. Profile the organization (OSINT)]]
- [[#2. Find subdomains]]
- [[#3. Down to infrastructure (IP, ports, services)]]
- [[#4. Map the web surface]]
- [[#5. Content discovery]]
- [[#6. Recon autoscan]]

---

## 0. Automation & orchestration
*Frameworks that chain the individual tools below into one pipeline. Use them for coverage and repeatability — but they inherit the same rule: passive stages are safe, active/scan stages are noisy and need approval. Read the config before running; defaults can be aggressive.*

| Tool | Purpose |
|---|---|
| [`reconftw`](https://github.com/six2dez/reconftw) | the reference all-in-one bash pipeline (OSINT → subdomains → hosts → web surface → content → vuln checks). Modular flags (`-r` recon, `-s` subs, `-w` web, `-a` all), resumable, notifies via notify. Maps almost 1:1 to sections 1–6 below. |
| [`akca`](https://github.com/Dheerajmadhukar/akca) | recon automation that wires ProjectDiscovery-style tooling into a single flow; lighter/scriptable alternative to reconftw. |
| [`bbot`](https://github.com/blacklanternsecurity/bbot) | recursive, modular recon engine (subdomain → http → nuclei); Python, graph-based, good for very wide scope. |
| [`Osmedeus`](https://github.com/j3ssie/osmedeus) | orchestration framework with a workflow engine and web UI; runs distributed. |
| [`reNgine`](https://github.com/yogeshojha/rengine) | recon platform with a web dashboard, scan engines (YAML), scheduling and reporting. |
| [`trickest`](https://github.com/trickest) | cloud workflow builder; drag-and-chain PD/OSS tools into DAG pipelines at scale. |
| [`Sn1per`](https://github.com/1N3/Sn1per) | commercial/community attack-surface scanner that bundles recon + vuln stages. |
| [`lazyrecon`](https://github.com/nahamsec/lazyrecon) / [`LazyRecon`](https://github.com/nahamsec/lazyrecon) | lightweight bash recon wrappers for quick target sweeps. |
| [`nuclei`](https://github.com/projectdiscovery/nuclei) workflows / [`pdtm`](https://github.com/projectdiscovery/pdtm) | ProjectDiscovery's own glue: `pdtm -ia` installs the suite; nuclei workflows chain templates. Roll your own pipeline with `subfinder \| dnsx \| naabu \| httpx \| nuclei \| notify`. |


## 1. Profile the organization (OSINT)
*Look at the org before the infrastructure. Nothing here touches the target.*

**WHOIS & sibling domains**

| Tool | Purpose |
|---|---|
| [`whois`](https://linux.die.net/man/1/whois) | domain registration details. |
| [`whoisxmlapi`](https://www.whoisxmlapi.com/) | reverse-whois by org/registrant email → sibling domains DNS won't reveal. |
| [`certstream`](https://github.com/CaliDog/certstream-python) | real-time CT log stream; see new subdomains before they hit production. |

**Leaked emails & credentials**

| Tool | Purpose |
|---|---|
| [`emailfinder`](https://github.com/Josue87/EmailFinder) | harvest emails per domain → reveals internal naming convention. |
| [`LeakSearch`](https://github.com/JoelGMSec/LeakSearch) | look up leaked credentials by domain/email across public dumps. |
| [`h8mail`](https://github.com/khast3x/h8mail) | email breach lookup, chains many sources (with/without API key). |
| [`holehe`](https://github.com/megadose/holehe) | which services an email is registered on, without sending mail. |

**GitHub & secrets**

| Tool | Purpose |
|---|---|
| [`enumerepo`](https://github.com/trickest/enumerepo) | list org + member repos before scanning for secrets. |
| [`github-search`](https://github.com/gwen001/github-search) / [`github-subdomains`](https://github.com/gwen001/github-subdomains) / [`github-endpoints`](https://github.com/gwen001/github-endpoints) | internal names, subdomains and endpoints mentioned in public code. |
| [`trufflehog`](https://github.com/trufflesecurity/trufflehog) | entropy + hundreds of detectors, verifies keys are still live. |
| [`gitleaks`](https://github.com/gitleaks/gitleaks) | fast secret scan in repos/history. |
| [`noseyparker`](https://github.com/praetorian-inc/noseyparker) | very fast tree/history secret scan; different ruleset than trufflehog. |
| [`titus`](https://github.com/RedHatProductSecurity/titus) | repo secret scan with custom rules (third engine when you want certainty). |
| [`gato`](https://github.com/praetorian-inc/gato) | audit GitHub Actions (self-hosted runners, "pwn request", public artifacts). |

**Search-engine dorking**

| Tool | Purpose |
|---|---|
| [`dorks_hunter`](https://github.com/six2dez/dorks_hunter) | prebuilt Google dorks per domain into one file. |
| [`xnldorker`](https://github.com/xnl-h4ck3r/xnldorker) | dork across multiple engines at once (covers where Google blocks automation). |

**M365 / Azure**

| Tool | Purpose |
|---|---|
| [`msftrecon`](https://github.com/Tw1sm/msftrecon) | tenant id, domains and federation type of an org on M365. |

**Indexed document metadata**

| Tool | Purpose |
|---|---|
| [`metagoofil`](https://github.com/opsdisk/metagoofil) | download indexed Office/PDF docs, then extract metadata. |
| [`exiftool`](https://exiftool.org/) | read metadata from downloaded files (use right after metagoofil). |

**Exposed APIs (Postman / Swagger)**

| Tool | Purpose |
|---|---|
| [`porch-pirate`](https://github.com/MandConsultingGroup/porch-pirate) | public Postman workspaces (often leak internal endpoints + tokens). |
| [`postleaksNg`](https://github.com/cosad3s/postleaks) | keyword scan of Postman for secrets. |
| [`SwaggerSpy`](https://github.com/UndeadSec/SwaggerSpy) | public Swagger/OpenAPI docs of an org. |

**Third-party misconfig**

| Tool | Purpose |
|---|---|
| [`misconfig-mapper`](https://github.com/intigriti/misconfig-mapper) | public third-party services (Jira, Confluence, Slack, Zendesk…) by org name. |

**Mail hygiene / spoofing**

| Tool | Purpose |
|---|---|
| [`spoofcheck`](https://github.com/BishopFox/spoofcheck) | can the domain be spoofed? (SPF/DMARC, no mail sent). |
| [`dmarc-lookup`](https://github.com/nathanwr/dmarc-lookup) | read and explain the DMARC record. |

**Cloud storage**

| Tool | Purpose |
|---|---|
| [`cloud_enum`](https://github.com/initstring/cloud_enum) | AWS/Azure/GCP buckets by org keyword. *Note: no Alibaba OSS coverage — check that separately.* |
| [`S3Scanner`](https://github.com/sa7mon/S3Scanner) | enumerate and check S3-style buckets for exposure. |

## 2. Find subdomains
*Each tool is a different **source** — none is complete. Run them all, then merge with `anew`.*

**Passive sources**

| Tool | Purpose |
|---|---|
| [`subfinder`](https://github.com/projectdiscovery/subfinder) | passive enum across dozens of APIs (quality depends on configured API keys). |
| [`amass`](https://github.com/owasp-amass/amass) | passive + active, plus intel (reverse-whois, ASN, org). |
| [`chaos`](https://github.com/projectdiscovery/chaos-client) | ProjectDiscovery's subdomain dataset (needs API key). |
| [`crt`](https://github.com/cemulus/crt) | Certificate Transparency (crt.sh); earliest leak of environment names. |

**Bruteforce & resolve**

| Tool | Purpose |
|---|---|
| [`puredns`](https://github.com/d3mondev/puredns) | large-scale brute + resolve with proper wildcard filtering. |
| [`massdns`](https://github.com/blechschmidt/massdns) | high-speed resolver engine under puredns; use directly for fine control. |
| [`dnsvalidator`](https://github.com/vortexau/dnsvalidator) | filter live, correct resolvers (skip this and brute returns garbage). |
| [`dnsx`](https://github.com/projectdiscovery/dnsx) | mass resolve, filter by rcode (NOERROR), all record types. The DNS-phase multitool. |

**Permutations**

| Tool | Purpose |
|---|---|
| [`gotator`](https://github.com/Josue87/gotator) | permutations from known names (dev/stg/sequence). Primary permutation engine. |
| [`regulator`](https://github.com/cramppet/regulator) | learns naming rules from existing subdomains, then generates candidates. |
| [`subwiz`](https://github.com/hadriansecurity/subwiz) | ML model guesses subdomains rule-based methods miss. |

**From web / metadata**

| Tool | Purpose |
|---|---|
| [`urlfinder`](https://github.com/projectdiscovery/urlfinder) / [`waymore`](https://github.com/xnl-h4ck3r/waymore) | pull hostnames from passive URL sources. |
| [`httpx`](https://github.com/projectdiscovery/httpx) | live web metadata as a source. |
| [`csprecon`](https://github.com/edoardottt/csprecon) | trusted domains from Content-Security-Policy (rarely inspected, often leaks internal APIs). |
| [`AnalyticsRelationships`](https://github.com/Josue87/AnalyticsRelationships) | sites sharing a Google Analytics/Tag Manager id. |

**From TLS / IP**

| Tool | Purpose |
|---|---|
| [`tlsx`](https://github.com/projectdiscovery/tlsx) | mass TLS handshake for CN/SAN, even on non-standard ports. |
| [`hakip2host`](https://github.com/hakluke/hakip2host) | IP → hostname (PTR, TLS certs); find hosts nothing points to. |

**Prioritize recursive brute**

| Tool | Purpose |
|---|---|
| [`dsieve`](https://github.com/trickest/dsieve) | rank subdomain branches by density to decide which to brute recursively. |

**Subdomain / DNS takeover**

| Tool | Purpose |
|---|---|
| [`can-i-take-over-xyz`](https://github.com/EdOverflow/can-i-take-over-xyz) | reference table of which services are takeover-prone and the signatures. |
| [`dnsReaper`](https://github.com/punk-security/dnsReaper) | fast takeover scanner, many signatures. |
| [`Subdominator`](https://github.com/Stratus-Security/Subdominator) | takeover detection with low false positives. |
| [`subjack`](https://github.com/haccer/subjack) | takeover detection per-provider fingerprints. |
| [`dnstake`](https://github.com/pwnesia/dnstake) | takeover at the nameserver level (NS delegated to a decommissioned provider). |
| [`nuclei`](https://github.com/projectdiscovery/nuclei) | takeover templates. |

**Zone transfer & merge**

| Tool | Purpose |
|---|---|
| [`dig`](https://linux.die.net/man/1/dig) | check for misconfigured DNS zone transfer (AXFR). |
| [`anew`](https://github.com/tomnomnom/anew) | append only lines not already in the target file. Foundation of any diff/monitoring flow. |

## 3. Down to infrastructure (IP, ports, services)
*From names to infra — ASN, CDN, open ports, services, version CVEs.*

**ASN & IP ownership**

| Tool | Purpose |
|---|---|
| [`asnmap`](https://github.com/projectdiscovery/asnmap) | org/IP → ASN and prefixes. Opens up reverse recon from IP ranges. |
| [`ipinfo`](https://ipinfo.io/) | owner, ASN, location for IPs in bulk; group infrastructure. |
| [`shodan`](https://www.shodan.io/) | pre-scanned internet data (ports, banners, favicon hash, certs). Doesn't touch target. |

**CDN / WAF**

| Tool | Purpose |
|---|---|
| [`cdncheck`](https://github.com/projectdiscovery/cdncheck) | flag IPs behind CDN/WAF. Port-scanning a CDN IP scans the wrong provider. |
| [`wafw00f`](https://github.com/EnableSecurity/wafw00f) | identify WAF before firing payloads. |

**Port scanning**

| Tool | Purpose |
|---|---|
| [`naabu`](https://github.com/projectdiscovery/naabu) | fast wide port scan, feed results into nmap. |
| [`nmap`](https://nmap.org) | deep scan (optionally after naabu). |
| [`smap`](https://github.com/s0md3v/Smap) | "passive nmap" via Shodan data; no packets to target (silent phase of red team). |

**Service detail & CVEs**

| Tool | Purpose |
|---|---|
| [`nerva`](https://github.com/hueristiq/nerva) | fingerprint services per host:port, more detail than a raw banner. |
| [`vulners`](https://github.com/vulnersCom/nmap-vulners) | nmap script matching service version to CVE DB. Hypothesis only — verify. |

**Password spraying (separate approval required)**

| Tool | Purpose |
|---|---|
| [`brutespray`](https://github.com/x90skysn3k/brutespray) | spray credentials against services from nmap output. |
| [`brutus`](https://github.com/rondox/brutus) | spray engine with pacing to avoid account lockout. |

## 4. Map the web surface
*Turn a list of names into a list of apps.*

| Tool | Purpose |
|---|---|
| [`httpx`](https://github.com/projectdiscovery/httpx) | probe hosts: status, title, tech, server. First step of any web recon. |
| [`gowitness`](https://github.com/sensepost/gowitness) | bulk screenshots. Skimming a few hundred images beats reading a few hundred lines. |
| [`aquatone`](https://github.com/michenriksen/aquatone) | screenshots grouped by similar UI clusters (alternative to gowitness). |
| [`VhostFinder`](https://github.com/wdahlenburg/VhostFinder) | hidden virtual hosts on an IP via Host header, with a verify step. |
| [`CMSeeK`](https://github.com/Tuhinshubhra/CMSeeK) | identify CMS + version in bulk → opens core/plugin CVE paths. |
| [`wpscan`](https://github.com/wpscanteam/wpscan) | deep WordPress (plugins, themes, users, version). Most CVEs live in plugins. |
| [`favirecon`](https://github.com/edoardottt/favirecon) | tech by favicon hash; hash is reverse-searchable on Shodan for similar hosts. |
| [`wappalyzer`](https://github.com/wappalyzer/wappalyzer) / [`WhatWeb`](https://github.com/urbanadventurer/WhatWeb) | framework/library/service fingerprint from page content. |
| [`testssl`](https://github.com/drwetter/testssl.sh) | full SSL/TLS audit (old protocols, weak ciphers, bad certs). Runs in bulk. |
| [`sslyze`](https://github.com/nabla-c0d3/sslyze) | TLS as a library/CLI, clean JSON output for pipelines. |

## 5. Content discovery
*Inside each app — URLs, JS bundles, source maps, hidden params, GraphQL/WS/gRPC, hidden dirs, target-specific wordlists.*

**Gather URLs**

| Tool | Purpose |
|---|---|
| [`urlfinder`](https://github.com/projectdiscovery/urlfinder) | URLs from many passive sources (modern gau replacement). |
| [`waymore`](https://github.com/xnl-h4ck3r/waymore) | URLs *and* archived content from Wayback/CommonCrawl/URLScan (deeper than gau). |
| [`gau`](https://github.com/lc/gau) | historical URLs from Wayback/CommonCrawl/AlienVault; endpoints removed from the UI. |
| [`katana`](https://github.com/projectdiscovery/katana) | active crawler, parses JS for endpoints. Pair with gau for max coverage. |
| [`hakrawler`](https://github.com/hakluke/hakrawler) / [`gospider`](https://github.com/jaeles-project/gospider) | fast crawlers for shell pipelines (gospider parses JS + forms). |

**Trim & classify URLs**

| Tool | Purpose |
|---|---|
| [`urless`](https://github.com/xnl-h4ck3r/urless) / [`uro`](https://github.com/s0md3v/uro) | collapse URLs to a representative set (drop param-only duplicates). |
| [`gf`](https://github.com/tomnomnom/gf) + [`gf-patterns`](https://github.com/1ndianl33t/Gf-Patterns) | filter URLs by vuln pattern (xss, sqli, ssrf, lfi, redirect) → a test queue. |

**JavaScript analysis**

| Tool | Purpose |
|---|---|
| [`subjs`](https://github.com/lc/subjs) | list JS files from a page (start of bundle analysis). |
| [`jsluice`](https://github.com/BishopFox/jsluice) | URLs/endpoints/secrets from JS via AST (more accurate than regex). |
| [`xnLinkFinder`](https://github.com/xnl-h4ck3r/xnLinkFinder) | endpoints + params from JS/HTML, including downloaded files. |
| [`JSA`](https://github.com/w9w/JSA) | JS analysis: endpoints, secrets, hidden paths. |
| [`mantra`](https://github.com/MrEmpy/mantra) | embedded API keys in JS bundles and HTML. |
| [`getjswords`](https://github.com/m4ll0k/BBTz) | extract keywords from JS to build target-specific param/path wordlists. |

- `LinkFinder` (burp-js-linkfinder-enhanced) — endpoints in JS bundles inside Burp.

| Tool | Purpose |
|---|---|
| [`sourcemapper`](https://github.com/denandz/sourcemapper) | decode `.js.map` into original source (comments, var names, undeployed files). |

**Hidden parameters**

| Tool | Purpose |
|---|---|
| [`arjun`](https://github.com/s0md3v/Arjun) | hidden HTTP params (GET/POST/JSON) not in the UI. |
| [`x8`](https://github.com/Sh1Yo/x8) | high-speed hidden param discovery, many body/header styles. |
| [`Param Miner`](https://github.com/PortSwigger/param-miner) | Burp extension; guesses headers/params outside the cache key (needed for cache poisoning). |

**GraphQL / WebSocket / gRPC**

| Tool | Purpose |
|---|---|
| [`GQLSpection`](https://github.com/doyensec/GQLSpection) | GraphQL introspection + schema reading; infers ops even when introspection is off. |
| [`grpcurl`](https://github.com/fullstorydev/grpcurl) | probe gRPC; list services via server reflection if enabled. |
| [`websocat`](https://github.com/vi/websocat) / [`wscat`](https://github.com/websockets/wscat) | WebSocket clients from CLI (websocat sets arbitrary Origin to test handshake). |

**Directory / file discovery**

| Tool | Purpose |
|---|---|
| [`ffuf`](https://github.com/ffuf/ffuf) | fuzz dirs/files/params/vhosts. Fast, flexible filters (`-ac` auto-baseline). |
| [`feroxbuster`](https://github.com/epi052/feroxbuster) | recursive fuzz with link extraction; good for deep trees. |
| [`dirsearch`](https://github.com/maurosoria/dirsearch) | dir fuzz with solid built-in wordlists for a quick start. |
| [`shortscan`](https://github.com/bitquark/shortscan) | exploit IIS 8.3 shortname to guess file/dir names instead of blind brute. |
| [`iis-shortname-scanner`](https://github.com/irsdl/IIS-ShortName-Scanner) | Java version of the same technique. |

**Target-specific wordlists**

| Tool | Purpose |
|---|---|
| [`cewl`](https://github.com/digininja/CeWL) / [`cewler`](https://github.com/roys/cewler) | build wordlists from site content (cewler also makes password dictionaries). |
| [`tok`](https://github.com/tomnomnom/hacks) | split content into tokens for wordlists; pipes well. |
| [`wordlistgen`](https://github.com/ameenmaali/wordlistgen) | context wordlists from gathered URLs. |

- Reference sets: [`SecLists`](https://github.com/danielmiessler/SecLists), [`OneListForAll`](https://github.com/six2dez/OneListForAll), [`leaky-paths`](https://github.com/ayoubfathi/leaky-paths), [`Auto_Wordlists`](https://github.com/carlospolop/Auto_Wordlists).

**LLM service (optional)**

| Tool | Purpose |
|---|---|
| [`julius`](https://github.com/rockerritesh/julius) | fingerprint exposed LLM/AI services on discovered web/API endpoints. |

## 6. Recon autoscan
*A wide net so easy wins aren't missed. Everything here is **noisy — requires approval, and every result must be hand-verified**.*

| Tool | Purpose |
|---|---|
| [`nuclei`](https://github.com/projectdiscovery/nuclei) | CVE/misconfig/exposure templates; also `nuclei -dast` over collected URLs + gf candidates. |
| [`bbot`](https://github.com/blacklanternsecurity/bbot) | recursive automated recon (subdomain → http → nuclei) for wide scope. |
| [`dalfox`](https://github.com/hahwul/dalfox) | context-aware reflected-XSS scanner (not blind payloads). |
| [`kxss`](https://github.com/Emoe/kxss) | quickly flag reflected params with unescaped chars; run before dalfox (cheaper). |
| [`ghauri`](https://github.com/r0oth3x49/ghauri) | detect/exploit SQLi, faster detection than sqlmap. |
| [`crlfuzz`](https://github.com/dwisiswant0/crlfuzz) | bulk CRLF injection over a URL list. |
| [`commix`](https://github.com/commixproject/commix) | command injection detect/exploit. Stop PoC at `id`/`whoami` on real systems. |
| [`smugglex`](https://github.com/Moopinger/smugglex) | bulk HTTP request smuggling. Affects other users — pick off-peak hours. |
| [`Web-Cache-Vulnerability-Scanner`](https://github.com/Hackmanit/Web-Cache-Vulnerability-Scanner) / [`toxicache`](https://github.com/xhzeem/toxicache) | cache poisoning/deception at scale. |
| [`nomore403`](https://github.com/devploit/nomore403) | bypass 401/403 via path/header/method variants. |
| [`second-order`](https://github.com/mhmdiaa/second-order) | dead external links/resources → app-layer takeover source. |
| [`socialhunter`](https://github.com/utkusen/socialhunter) | abandoned social links you can re-register. |
| [`broken-link-checker`](https://github.com/stevenvachon/broken-link-checker) | broken links → input for finding expired domains. |

---
See also: [[README]] · [[Web Cheatsheet]]
