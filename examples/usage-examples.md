# urlX Usage Examples

This document provides practical examples for using urlX in various scenarios.

## Table of Contents

- [Basic Usage](#basic-usage)
- [Bug Bounty Hunting](#bug-bounty-hunting)
- [Penetration Testing](#penetration-testing)
- [Security Research](#security-research)
- [Integration with Other Tools](#integration-with-other-tools)
- [Advanced Techniques](#advanced-techniques)

## Basic Usage

### Single Domain Discovery

```bash
# Basic scan
urlx -domain example.com

# Verbose output
urlx -domain example.com -v

# Save to file
urlx -domain example.com -o urls.txt
```

### Multiple Domains from File

Create a file `domains.txt`:
```
example.com
test.example.com
api.example.com
```

Run urlX:
```bash
# Process all domains
urlx -d domains.txt -v -o all-urls.txt

# With higher concurrency
urlx -d domains.txt -c 10 -v
```

## Bug Bounty Hunting

### Complete Reconnaissance Workflow

```bash
# 1. Subdomain enumeration
subfinder -d target.com -silent | tee subdomains.txt
assetfinder --subs-only target.com >> subdomains.txt
sort -u subdomains.txt -o subdomains.txt

# 2. Discover URLs from all sources
urlx -d subdomains.txt \
  -urlscan-key $URLSCAN_KEY \
  -otx-key $OTX_KEY \
  -vt-key $VT_KEY \
  -v -o discovered-urls.txt

# 3. Filter live URLs
cat discovered-urls.txt | httpx -silent -mc 200,301,302,403 -o live-urls.txt

# 4. Find interesting endpoints
cat live-urls.txt | grep -E '\.(js|json|xml|txt|log|bak)$' > interesting.txt
```

### Finding Hidden Parameters

```bash
# Discover URLs
urlx -domain target.com -v | tee urls.txt

# Extract unique parameters
cat urls.txt | unfurl keys | sort -u > params.txt

# Test parameters for vulnerabilities
cat params.txt | while read param; do
  echo "Testing: $param"
  # Add your parameter fuzzing logic here
done
```

### API Endpoint Discovery

```bash
# Find API endpoints
urlx -domain api.target.com -v | grep -E '/api/|/v[0-9]+/' | tee api-endpoints.txt

# Extract API versions
cat api-endpoints.txt | grep -oP '/v\d+/' | sort -u

# Find GraphQL endpoints
cat api-endpoints.txt | grep -i graphql
```

## Penetration Testing

### Information Gathering Phase

```bash
# Comprehensive URL discovery with all API keys
urlx -domain target.com \
  -urlscan-key $URLSCAN_KEY \
  -otx-key $OTX_KEY \
  -vt-key $VT_KEY \
  -securitytrails-key $ST_KEY \
  -github-key $GITHUB_TOKEN \
  -censys-id $CENSYS_ID \
  -censys-secret $CENSYS_SECRET \
  -v -o recon-urls.txt

# Find admin panels
cat recon-urls.txt | grep -iE 'admin|panel|dashboard|cpanel|login' > admin-urls.txt

# Find backup files
cat recon-urls.txt | grep -iE '\.(bak|old|backup|swp|save)$' > backups.txt
```

### Technology Fingerprinting

```bash
# Find technology-specific paths
urlx -domain target.com -v | tee all-urls.txt

# PHP applications
grep -E '\.php|/wp-|/admin\.php' all-urls.txt > php-apps.txt

# JavaScript frameworks
grep -E '\.js$|/static/|/assets/' all-urls.txt > js-resources.txt

# Python/Django
grep -E '/django|\.py|/api/' all-urls.txt > python-apps.txt
```

## Security Research

### Certificate Transparency Analysis

```bash
# Focus on certificate sources
urlx -domain target.com -v 2>&1 | grep -A 5 "crt.sh\|Censys"

# Find staging/dev environments
urlx -domain target.com | grep -iE 'staging|dev|test|uat|preprod'
```

### Historical Data Mining

```bash
# Find archived content
urlx -domain old-site.com -v 2>&1 | grep -A 5 "Wayback\|Archive"

# Compare with current state
urlx -domain site.com | sort > current.txt
urlx -domain site.com -v 2>&1 | grep "Wayback" | cut -d' ' -f5 | sort > historical.txt
comm -13 current.txt historical.txt > removed-urls.txt
```

## Integration with Other Tools

### With httpx

```bash
# Discover and probe URLs
urlx -d targets.txt | httpx -silent -threads 50 -status-code -title

# Filter by status code
urlx -domain target.com | httpx -mc 200,403 -silent
```

### With nuclei

```bash
# Scan discovered URLs for vulnerabilities
urlx -d domains.txt -o urls.txt
cat urls.txt | nuclei -t cves/ -t exposures/

# Focus on specific technologies
urlx -domain target.com | grep -i 'wordpress' | nuclei -t wordpress/
```

### With ffuf

```bash
# Directory bruteforcing on discovered domains
urlx -domain target.com | unfurl domains | sort -u | while read domain; do
  ffuf -w wordlist.txt -u https://$domain/FUZZ -mc 200,301,302,403
done
```

### With waybackurls

```bash
# Combine urlX with waybackurls
urlx -domain target.com > urlx-results.txt
waybackurls target.com > wayback-results.txt
cat urlx-results.txt wayback-results.txt | sort -u > combined.txt
```

### With gau (GetAllUrls)

```bash
# Merge results from multiple sources
urlx -domain target.com -o urlx.txt
gau target.com > gau.txt
cat urlx.txt gau.txt | sort -u > all-urls.txt
```

## Advanced Techniques

### Recursive Subdomain Discovery

```bash
#!/bin/bash
domain=$1

# Initial subdomain discovery
subfinder -d $domain -silent > subs.txt

# Discover URLs from subdomains
urlx -d subs.txt -v -o urls.txt

# Extract new subdomains from URLs
cat urls.txt | unfurl domains | sort -u > new-subs.txt

# Find differences
comm -13 <(sort subs.txt) <(sort new-subs.txt) > additional-subs.txt

# Recurse if new subdomains found
if [ -s additional-subs.txt ]; then
  echo "Found new subdomains, running urlX again..."
  urlx -d additional-subs.txt -v >> urls.txt
fi
```

### Monitoring for New URLs

```bash
#!/bin/bash
# Script: monitor-urls.sh

DOMAIN=$1
OUTPUT_DIR="monitoring"
mkdir -p $OUTPUT_DIR

# Get current URLs
urlx -domain $DOMAIN -v -o $OUTPUT_DIR/current-$(date +%Y%m%d).txt

# Compare with previous scan
PREVIOUS=$(ls -t $OUTPUT_DIR/current-*.txt | sed -n 2p)

if [ -n "$PREVIOUS" ]; then
  comm -13 <(sort $PREVIOUS) <(sort $OUTPUT_DIR/current-$(date +%Y%m%d).txt) > $OUTPUT_DIR/new-urls.txt
  
  if [ -s $OUTPUT_DIR/new-urls.txt ]; then
    echo "New URLs found:"
    cat $OUTPUT_DIR/new-urls.txt
    # Send notification (customize as needed)
    # notify-send "New URLs" "$(wc -l < $OUTPUT_DIR/new-urls.txt) new URLs found"
  fi
fi
```

### Filtering by File Extensions

```bash
# JavaScript files
urlx -domain target.com | grep -E '\.js$' > javascript-files.txt

# Configuration files
urlx -domain target.com | grep -iE '\.(json|xml|yml|yaml|conf|config|env)$' > configs.txt

# Documents
urlx -domain target.com | grep -iE '\.(pdf|doc|docx|xls|xlsx)$' > documents.txt

# Images (potentially interesting metadata)
urlx -domain target.com | grep -iE '\.(jpg|jpeg|png|gif|svg)$' > images.txt
```

### Pattern-Based Analysis

```bash
# Find potential IDOR endpoints
urlx -domain target.com | grep -E '/user/[0-9]+|/id=[0-9]+|/profile/[0-9]+'

# Find potential SQL injection points
urlx -domain target.com | grep -E '\?.*id=|search=|query='

# Find file upload endpoints
urlx -domain target.com | grep -iE 'upload|file|attachment'

# Find password reset endpoints
urlx -domain target.com | grep -iE 'reset|forgot|password|recovery'
```

### Bulk Processing with Parallel

```bash
# Install GNU parallel if not already installed
# sudo apt install parallel

# Process domains in parallel
cat domains.txt | parallel -j 10 "urlx -domain {} -o results/{}.txt -v"

# Merge all results
cat results/*.txt | sort -u > all-results.txt
```

### Docker Usage

```bash
# Run in Docker
docker run --rm -v $(pwd)/output:/output urlx:latest \
  -domain target.com -o /output/urls.txt -v

# With API keys via environment
docker run --rm \
  -e URLSCAN_KEY=$URLSCAN_KEY \
  -e OTX_KEY=$OTX_KEY \
  urlx:latest -domain target.com \
  -urlscan-key $URLSCAN_KEY \
  -otx-key $OTX_KEY -v
```

## Best Practices

1. **Always use verbose mode** during initial testing to understand what's working
2. **Rate limiting**: Be respectful of API rate limits, use appropriate concurrency
3. **Save everything**: Always save results to files for later analysis
4. **Combine tools**: Don't rely on a single tool, combine multiple sources
5. **Regular updates**: Run discovery regularly to catch new endpoints
6. **Deduplicate**: Always deduplicate your results
7. **Organize output**: Use descriptive filenames and organized directory structures

## Tips and Tricks

- Use `tee` to both save and display output
- Combine with `watch` for continuous monitoring
- Use `jq` to parse JSON responses from APIs
- Set up cron jobs for regular scanning
- Create shell aliases for common commands
- Use tmux/screen for long-running scans
