# acuscan
lets test an acunetix db for own python implementation

usage: scanner.py [-h] [-u string] [-l string] [-o string] [-oh string] [-ooh string] [-silent] [-nc] [-v] [-fr] [-fhr] [-mr int] [-dr]
                  [-severity string] [-db string] [-ua string] [-crawl-depth int] [-crawl-max int] [-timeout int] [-proxy URL] [-rl int] [-trl int]
                  [-bs int] [-c int] [-upac [path]] [-acuconvupdate [BIN]] [-cupz [path]] [-upuz [path]]

HexStrike Web Vulnerability Scanner v2.0.0

options:
  -h, --help                                             show this help message and exit

TARGET:
  -u, -target, --target string                           Target URL(s) to scan
  -l, -list, --list string                               File containing list of target URLs

OUTPUT:
  -o, -output, --output string                           Output text report file (.txt)
  -oh, -output-html, --output-html string                Output HTML report file (.html) with sortable/filterable table
  -ooh, -output-both, --output-both string               Output both text (.txt) and HTML (.html) reports
  -silent, --silent                                      Show only findings
  -nc, -no-color, --no-color                             Disable colored output
  -v, -verbose, --verbose                                Verbose output

CONFIGURATIONS:
  -fr, -follow-redirects, --follow-redirects             Follow HTTP redirects (default: true)
  -fhr, -follow-host-redirects, --follow-host-redirects  Follow redirects on the same host only
  -mr, -max-redirects, --max-redirects int               Max number of redirects (default: 10)
  -dr, -disable-redirects, --disable-redirects           Disable following redirects
  -severity, --severity string                           Filter by severity (critical,high,medium,low,info)
  -db, --database string                                 Checks database path (default: data/checks_db.json)
  -ua, -user-agent, --user-agent string                  Custom User-Agent string
  -crawl-depth, --crawl-depth int                        Maximum crawl depth (default: 3)
  -crawl-max, --crawl-max int                            Maximum pages to crawl (default: 200)
  -timeout, --timeout int                                HTTP request timeout in seconds (default: 10)
  -proxy, --proxy URL                                    Proxy URL (http://host:port, https://host:port, socks4://host:port, socks5://host:port)

RATE-LIMIT:
  -rl, -rate-limit, --rate-limit int                     Global max requests per second (default: 1000)
  -trl, -target-rate-limit, --target-rate-limit int      Max requests per second per target (default: 150)
  -bs, -bulk-size, --bulk-size int                       Number of targets to scan in parallel (default: 25)
  -c, -concurrency, --concurrency int                    Number of concurrent checks per target (default: 25)

DATABASE UPDATE:
  -upac, --update-from-acunetix [path]                   Update DB from local Acunetix scripts (auto-detect or path)
  -acuconvupdate, --acunetix-conv-db-to-update [BIN]     Convert Acunetix security .bin to scanner update archive
  -cupz, --create-archive [path]                         Create portable database archive (updatedbd_VERSION.tgz)
  -upuz, --update-from-archive [path]                    Update DB from archive (updatedbd_VERSION.tgz)

SCAN:
  python3 scanner.py -u https://target.com
  python3 scanner.py -u https://target1.com -u https://target2.com
  python3 scanner.py -l targets.txt -o results.json -c 50

DATABASE UPDATE:
  python3 scanner.py -upac                                   Extract from local Acunetix (auto-detect)
  python3 scanner.py -upac /path/to/Scripts                   Extract from specific path
  python3 scanner.py -acuconvupdate security_251107103.bin    Convert Acunetix .bin and create update archive
  python3 scanner.py -cupz                                    Create updatedbd_VERSION.tgz archive
  python3 scanner.py -upuz                                    Update from best archive (auto-find)
  python3 scanner.py -upuz /path/to/updatedbd_VERSION.tgz     Update from specific archive

EXAMPLES:
  python3 scanner.py -u https://target.com -c 50 -rl 200
  python3 scanner.py -u https://target.com -severity high,critical
  python3 scanner.py -l targets.txt -o results.json -bs 10 -c 30
