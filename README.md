# acuscan by neoleads

Python-based web vulnerability scanner utilizing Acunetix vulnerability database.

## Overview

A Custom implementation for testing and leveraging Acunetix vulnerability databases in Python. Supports extraction and conversion of Acunetix security bins for vulnerability scanning operations.

## Added databases

- **Windows**: v25.11.251107123 (`security_251107103.bin`)
- **Linux**: v25.1.250204093 (`security_250204086.bin`)

## Installation

```bash
git clone https://github.com/neolead/acuscan
cd acuscan
```

## Usage

```
scanner.py [-h] [-u URL] [-l FILE] [-o FILE] [-oh FILE] [-ooh FILE] 
           [-silent] [-nc] [-v] [-fr] [-fhr] [-mr INT] [-dr]
           [-severity LEVEL] [-db PATH] [-ua STRING] 
           [-crawl-depth INT] [-crawl-max INT] [-timeout INT] 
           [-proxy URL] [-rl INT] [-trl INT] [-bs INT] [-c INT]
           [-upac [PATH]] [-acuconvupdate [BIN]] 
           [-cupz [PATH]] [-upuz [PATH]]
```

## Options

### Target

```
-u, --target URL          Target URL(s) to scan
-l, --list FILE           File containing list of target URLs
```

### Output

```
-o, --output FILE         Output text report (.txt)
-oh, --output-html FILE   Output HTML report with sortable/filterable table
-ooh, --output-both FILE  Output both text and HTML reports
-silent                   Show only findings
-nc, --no-color           Disable colored output
-v, --verbose             Verbose output
```

### Configuration

```
-fr, --follow-redirects              Follow HTTP redirects (default: true)
-fhr, --follow-host-redirects        Follow redirects on same host only
-mr, --max-redirects INT             Max redirects (default: 10)
-dr, --disable-redirects             Disable following redirects
-severity LEVEL                      Filter by severity: critical, high, medium, low, info
-db, --database PATH                 Database path (default: data/checks_db.json)
-ua, --user-agent STRING             Custom User-Agent string
-crawl-depth INT                     Maximum crawl depth (default: 3)
-crawl-max INT                       Maximum pages to crawl (default: 200)
-timeout INT                         HTTP timeout in seconds (default: 10)
-proxy URL                           Proxy: http://, https://, socks4://, socks5://
```

### Rate Limiting

```
-rl, --rate-limit INT                Global max requests/sec (default: 1000)
-trl, --target-rate-limit INT        Max requests/sec per target (default: 150)
-bs, --bulk-size INT                 Parallel targets (default: 25)
-c, --concurrency INT                Concurrent checks per target (default: 25)
```

### Database Management

```
-upac, --update-from-acunetix [PATH]       Update from local Acunetix (auto-detect or path)
-acuconvupdate [BIN]                       Convert Acunetix .bin to update archive
-cupz, --create-archive [PATH]             Create portable archive (updatedbd_VERSION.tgz)
-upuz, --update-from-archive [PATH]        Update from archive (auto-find or path)
```

## Examples

### Basic Scanning

```bash
# Single target
python3 scanner.py -u https://target.com

# Multiple targets
python3 scanner.py -u https://target1.com -u https://target2.com

# Target list
python3 scanner.py -l targets.txt -o results.txt
```

### Advanced Scanning

```bash
# High performance scan
python3 scanner.py -u https://target.com -c 50 -rl 200

# Filter critical/high severity
python3 scanner.py -u https://target.com -severity high,critical

# Bulk scan with custom settings
python3 scanner.py -l targets.txt -o results.txt -bs 10 -c 30
```

### Database Operations

```bash
# Auto-detect and extract from local Acunetix
python3 scanner.py -upac

# Extract from specific path
python3 scanner.py -upac /path/to/Scripts

# Convert Acunetix .bin and create update archive
python3 scanner.py -acuconvupdate security_251107103.bin

# Create portable archive
python3 scanner.py -cupz

# Update from auto-detected archive
python3 scanner.py -upuz

# Update from specific archive
python3 scanner.py -upuz /path/to/updatedbd_VERSION.tgz
```

### First run

```
pip3 install -r reqirements.txt
python3 scanner.py -acuconvupdate security_251107103.bin
python3 scanner.py -upuz updatedbd_251107103.tgz
```


### Fun

Have it. telegream @neoleads

