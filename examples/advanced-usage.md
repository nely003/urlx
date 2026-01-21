# urlX Advanced Usage Examples

Complete examples combining discovery, crawling, probing, and filtering.

## Quick Reference

```bash
# Basic discovery
urlx -domain example.com

# Discovery + Crawling
urlx -domain example.com -crawl -depth 2

# Discovery + Probing
urlx -domain example.com -probe

# Discovery + Crawling + Probing
urlx -domain example.com -crawl -probe -v

# File filtering
urlx -domain example.com -crawl -only ".pdf"
urlx -domain example.com -crawl -remove ".png,.jpg"

# Complete workflow
urlx -d subdomains.txt -crawl -depth 3 -probe -mc 200,403 -only ".js,.json" -o results.txt
```

## Example 1: PDF Extraction from Bug Bounty Target

```bash
#!/bin/bash
# Extract all PDFs from a target domain

TARGET="target.com"
OUTPUT_DIR="pdf-extraction"

mkdir -p $OUTPUT_DIR

echo "[*] Step 1: Passive URL discovery"
urlx -domain $TARGET -v -o ${OUTPUT_DIR}/all-urls.txt

echo "[*] Step 2: Active crawling for PDFs"
urlx -u ${OUTPUT_DIR}/all-urls.txt \
  -crawl \
  -depth 3 \
  -only ".pdf" \
  -v \
  -o ${OUTPUT_DIR}/pdfs.txt

echo "[*] Step 3: Verify PDFs are accessible"
urlx -u ${OUTPUT_DIR}/pdfs.txt \
  -probe \
  -mc 200 \
  -o ${OUTPUT_DIR}/accessible-pdfs.txt

echo "[*] Step 4: Download PDFs"
mkdir -p ${OUTPUT_DIR}/downloads
cat ${OUTPUT_DIR}/accessible-pdfs.txt | awk '{print $2}' | while read pdf; do
    filename=$(basename "$pdf")
    echo "Downloading: $filename"
    wget -q "$pdf" -O "${OUTPUT_DIR}/downloads/$filename"
done

echo "[+] Complete!"
echo "    Total PDFs found: $(wc -l < ${OUTPUT_DIR}/pdfs.txt)"
echo "    Accessible PDFs: $(wc -l < ${OUTPUT_DIR}/accessible-pdfs.txt)"
echo "    Downloaded: $(ls ${OUTPUT_DIR}/downloads | wc -l)"
```

## Example 2: JavaScript File Analysis for Secrets

```bash
#!/bin/bash
# Find and analyze JavaScript files for sensitive data

TARGET="target.com"
WORKSPACE="js-analysis"

mkdir -p $WORKSPACE/{js,results}

echo "[*] Discovering and crawling for JavaScript files..."
urlx -domain $TARGET \
  -crawl \
  -depth 3 \
  -only ".js" \
  -remove ".min.js" \
  -v \
  -o $WORKSPACE/js-files.txt

echo "[*] Probing JavaScript files..."
urlx -u $WORKSPACE/js-files.txt \
  -probe \
  -mc 200 \
  -o $WORKSPACE/accessible-js.txt

echo "[*] Downloading JavaScript files..."
cat $WORKSPACE/accessible-js.txt | awk '{print $2}' | while read jsurl; do
    filename=$(echo "$jsurl" | md5sum | cut -d' ' -f1).js
    curl -s "$jsurl" -o "$WORKSPACE/js/$filename"
    echo "$jsurl" >> "$WORKSPACE/js/$filename.url"
done

echo "[*] Scanning for sensitive data..."

# API keys
echo "=== API Keys ===" > $WORKSPACE/results/findings.txt
grep -r -iE '(api[_-]?key|apikey|api[_-]?secret).*["\047][a-zA-Z0-9]{20,}["\047]' $WORKSPACE/js/ >> $WORKSPACE/results/findings.txt

# Tokens
echo -e "\n=== Tokens ===" >> $WORKSPACE/results/findings.txt
grep -r -iE '(access[_-]?token|auth[_-]?token|bearer).*["\047][a-zA-Z0-9]{20,}["\047]' $WORKSPACE/js/ >> $WORKSPACE/results/findings.txt

# AWS keys
echo -e "\n=== AWS Keys ===" >> $WORKSPACE/results/findings.txt
grep -r -E 'AKIA[0-9A-Z]{16}' $WORKSPACE/js/ >> $WORKSPACE/results/findings.txt

# Endpoints
echo -e "\n=== API Endpoints ===" >> $WORKSPACE/results/findings.txt
grep -r -E 'https?://[^"'\'']+/api/' $WORKSPACE/js/ | head -50 >> $WORKSPACE/results/findings.txt

# Passwords
echo -e "\n=== Potential Passwords ===" >> $WORKSPACE/results/findings.txt
grep -r -iE 'password.*["\047][^"\047]{8,}["\047]' $WORKSPACE/js/ >> $WORKSPACE/results/findings.txt

echo "[+] Analysis complete! Check $WORKSPACE/results/findings.txt"
```

## Example 3: Complete Subdomain Recon with File Extraction

```bash
#!/bin/bash
# Comprehensive reconnaissance with file categorization

TARGET="$1"
if [ -z "$TARGET" ]; then
    echo "Usage: $0 <domain>"
    exit 1
fi

WORKSPACE="recon-$TARGET-$(date +%Y%m%d)"
mkdir -p $WORKSPACE/{urls,files,probing}

echo "=== URLX COMPREHENSIVE RECON ==="
echo "Target: $TARGET"
echo "Workspace: $WORKSPACE"
echo ""

# Stage 1: Subdomain enumeration
echo "[1/7] Subdomain enumeration..."
subfinder -d $TARGET -silent -o $WORKSPACE/subdomains.txt
echo "  Found $(wc -l < $WORKSPACE/subdomains.txt) subdomains"

# Stage 2: Passive URL discovery
echo "[2/7] Passive URL discovery from all sources..."
urlx -d $WORKSPACE/subdomains.txt \
  -v \
  -o $WORKSPACE/urls/passive.txt
echo "  Discovered $(wc -l < $WORKSPACE/urls/passive.txt) URLs"

# Stage 3: Active crawling
echo "[3/7] Active crawling (depth=3)..."
urlx -u $WORKSPACE/urls/passive.txt \
  -crawl \
  -depth 3 \
  -remove ".png,.jpg,.gif,.svg,.woff,.woff2,.ttf,.eot" \
  -v \
  -o $WORKSPACE/urls/crawled.txt
echo "  Crawled $(wc -l < $WORKSPACE/urls/crawled.txt) URLs"

# Stage 4: Live probing
echo "[4/7] Probing for live hosts..."
urlx -u $WORKSPACE/urls/crawled.txt \
  -probe \
  -mc 200,201,301,302,401,403 \
  -c 20 \
  -v \
  -o $WORKSPACE/probing/alive.txt
echo "  Found $(wc -l < $WORKSPACE/probing/alive.txt) live hosts"

# Stage 5: File categorization
echo "[5/7] Extracting files by type..."

# JavaScript
urlx -u $WORKSPACE/urls/crawled.txt -only ".js" > $WORKSPACE/files/javascript.txt
echo "  JavaScript: $(wc -l < $WORKSPACE/files/javascript.txt)"

# Documents
urlx -u $WORKSPACE/urls/crawled.txt -only ".pdf,.doc,.docx,.xls,.xlsx" > $WORKSPACE/files/documents.txt
echo "  Documents: $(wc -l < $WORKSPACE/files/documents.txt)"

# Data files
urlx -u $WORKSPACE/urls/crawled.txt -only ".json,.xml,.yml,.yaml" > $WORKSPACE/files/data.txt
echo "  Data files: $(wc -l < $WORKSPACE/files/data.txt)"

# Config files
urlx -u $WORKSPACE/urls/crawled.txt -only ".conf,.config,.ini,.env" > $WORKSPACE/files/config.txt
echo "  Config files: $(wc -l < $WORKSPACE/files/config.txt)"

# Archives
urlx -u $WORKSPACE/urls/crawled.txt -only ".zip,.tar,.gz,.rar,.7z,.bak" > $WORKSPACE/files/archives.txt
echo "  Archives: $(wc -l < $WORKSPACE/files/archives.txt)"

# Stage 6: Interesting endpoints
echo "[6/7] Finding interesting endpoints..."
grep -iE 'admin|api|v[0-9]|dashboard|panel|login|auth|config|backup|test|dev|stage|internal' \
  $WORKSPACE/urls/crawled.txt > $WORKSPACE/urls/interesting.txt
echo "  Interesting: $(wc -l < $WORKSPACE/urls/interesting.txt)"

# Stage 7: Generate report
echo "[7/7] Generating report..."
cat << EOF > $WORKSPACE/REPORT.md
# Recon Report: $TARGET
**Date:** $(date)
**Generated by:** urlX

## Summary

- **Subdomains:** $(wc -l < $WORKSPACE/subdomains.txt)
- **Passive URLs:** $(wc -l < $WORKSPACE/urls/passive.txt)
- **Crawled URLs:** $(wc -l < $WORKSPACE/urls/crawled.txt)
- **Live Hosts:** $(wc -l < $WORKSPACE/probing/alive.txt)

## File Types

| Type | Count | Location |
|------|-------|----------|
| JavaScript | $(wc -l < $WORKSPACE/files/javascript.txt) | files/javascript.txt |
| Documents | $(wc -l < $WORKSPACE/files/documents.txt) | files/documents.txt |
| Data Files | $(wc -l < $WORKSPACE/files/data.txt) | files/data.txt |
| Config Files | $(wc -l < $WORKSPACE/files/config.txt) | files/config.txt |
| Archives | $(wc -l < $WORKSPACE/files/archives.txt) | files/archives.txt |

## Interesting Endpoints

Found $(wc -l < $WORKSPACE/urls/interesting.txt) potentially interesting endpoints.

### Top 20 Interesting URLs:
\`\`\`
$(head -20 $WORKSPACE/urls/interesting.txt)
\`\`\`

## Next Steps

1. Review interesting endpoints in \`urls/interesting.txt\`
2. Analyze JavaScript files for secrets
3. Check accessible config/data files
4. Test live endpoints for vulnerabilities
5. Download and review documents

## Files Generated

\`\`\`
$WORKSPACE/
├── subdomains.txt          # All discovered subdomains
├── urls/
│   ├── passive.txt         # Passively discovered URLs
│   ├── crawled.txt         # All crawled URLs
│   └── interesting.txt     # Filtered interesting endpoints
├── probing/
│   └── alive.txt           # Live hosts with status codes
├── files/
│   ├── javascript.txt      # All JS files
│   ├── documents.txt       # PDF, DOC, XLS files
│   ├── data.txt            # JSON, XML, YAML files
│   ├── config.txt          # Configuration files
│   └── archives.txt        # ZIP, TAR, etc.
└── REPORT.md              # This report
\`\`\`
EOF

cat $WORKSPACE/REPORT.md
echo ""
echo "[+] Recon complete! Report saved to $WORKSPACE/REPORT.md"
```

## Example 4: API Endpoint Discovery and Testing

```bash
#!/bin/bash
# Discover and test API endpoints

TARGET="api.example.com"
WORKSPACE="api-discovery"

mkdir -p $WORKSPACE/{endpoints,responses}

echo "[*] Discovering API endpoints..."
urlx -domain $TARGET \
  -crawl \
  -depth 3 \
  -v \
  -o $WORKSPACE/all-urls.txt

echo "[*] Filtering API endpoints..."
grep -E '/api/|/v[0-9]+/|/graphql|/rest/' $WORKSPACE/all-urls.txt > $WORKSPACE/endpoints/api.txt
echo "  Found $(wc -l < $WORKSPACE/endpoints/api.txt) API endpoints"

echo "[*] Probing API endpoints..."
urlx -u $WORKSPACE/endpoints/api.txt \
  -probe \
  -mc 200,201,401,403,404,500 \
  -json \
  -o $WORKSPACE/responses/probe-results.json

echo "[*] Analyzing responses..."

# Public endpoints (200)
jq -r 'select(.StatusCode == 200) | .URL' $WORKSPACE/responses/probe-results.json \
  > $WORKSPACE/endpoints/public.txt

# Auth required (401)
jq -r 'select(.StatusCode == 401) | .URL' $WORKSPACE/responses/probe-results.json \
  > $WORKSPACE/endpoints/auth-required.txt

# Forbidden (403)
jq -r 'select(.StatusCode == 403) | .URL' $WORKSPACE/responses/probe-results.json \
  > $WORKSPACE/endpoints/forbidden.txt

# Server errors (500)
jq -r 'select(.StatusCode == 500) | .URL' $WORKSPACE/responses/probe-results.json \
  > $WORKSPACE/endpoints/errors.txt

# Generate report
cat << EOF > $WORKSPACE/API-REPORT.txt
=== API Endpoint Discovery Report ===

Total endpoints found: $(wc -l < $WORKSPACE/endpoints/api.txt)

Status breakdown:
  - 200 (Public):        $(wc -l < $WORKSPACE/endpoints/public.txt)
  - 401 (Auth required): $(wc -l < $WORKSPACE/endpoints/auth-required.txt)
  - 403 (Forbidden):     $(wc -l < $WORKSPACE/endpoints/forbidden.txt)
  - 500 (Errors):        $(wc -l < $WORKSPACE/endpoints/errors.txt)

=== Public Endpoints ===
$(cat $WORKSPACE/endpoints/public.txt)

=== Auth Required ===
$(cat $WORKSPACE/endpoints/auth-required.txt)

=== Forbidden ===
$(cat $WORKSPACE/endpoints/forbidden.txt)

=== Server Errors (Potential Bugs) ===
$(cat $WORKSPACE/endpoints/errors.txt)
EOF

cat $WORKSPACE/API-REPORT.txt
```

## Example 5: Technology Stack Fingerprinting

```bash
#!/bin/bash
# Identify technologies used by target

TARGET="$1"
WORKSPACE="tech-stack"

mkdir -p $WORKSPACE

echo "[*] Crawling for assets..."
urlx -domain $TARGET \
  -crawl \
  -depth 2 \
  -v \
  -o $WORKSPACE/all-assets.txt

echo "[*] Probing with technology detection..."
urlx -u $WORKSPACE/all-assets.txt \
  -probe \
  -mc 200 \
  -json \
  -o $WORKSPACE/tech-results.json

echo "[*] Analyzing technology stack..."

# Extract technologies
jq -r '.Technologies[]?' $WORKSPACE/tech-results.json | sort -u > $WORKSPACE/technologies.txt

# JavaScript frameworks
echo "=== JavaScript Frameworks ===" > $WORKSPACE/tech-report.txt
cat $WORKSPACE/all-assets.txt | grep -iE 'react|vue|angular|ember|svelte|next\.js|nuxt' | head -10 >> $WORKSPACE/tech-report.txt

echo -e "\n=== CSS Frameworks ===" >> $WORKSPACE/tech-report.txt
cat $WORKSPACE/all-assets.txt | grep -iE 'bootstrap|tailwind|bulma|foundation|materialize' | head -10 >> $WORKSPACE/tech-report.txt

echo -e "\n=== Backend Indicators ===" >> $WORKSPACE/tech-report.txt
jq -r 'select(.Server) | "\(.URL) - \(.Server)"' $WORKSPACE/tech-results.json | head -10 >> $WORKSPACE/tech-report.txt

echo -e "\n=== Detected Technologies ===" >> $WORKSPACE/tech-report.txt
cat $WORKSPACE/technologies.txt >> $WORKSPACE/tech-report.txt

cat $WORKSPACE/tech-report.txt
```

## Example 6: Continuous Monitoring

```bash
#!/bin/bash
# Monitor target for new URLs/files daily

TARGET="target.com"
BASELINE="baseline"
TODAY=$(date +%Y%m%d)
MONITOR_DIR="monitoring/$TODAY"

mkdir -p $MONITOR_DIR

echo "[*] Running daily scan for $TARGET..."

# Full scan
urlx -domain $TARGET \
  -crawl \
  -depth 2 \
  -remove ".png,.jpg,.gif" \
  -v \
  -o $MONITOR_DIR/urls.txt

# File categorization
urlx -u $MONITOR_DIR/urls.txt -only ".js" > $MONITOR_DIR/js.txt
urlx -u $MONITOR_DIR/urls.txt -only ".pdf,.doc" > $MONITOR_DIR/docs.txt
urlx -u $MONITOR_DIR/urls.txt -only ".json,.xml" > $MONITOR_DIR/data.txt

# Compare with baseline
if [ -d "$BASELINE" ]; then
    echo "[*] Comparing with baseline..."
    
    # New URLs
    comm -13 <(sort $BASELINE/urls.txt) <(sort $MONITOR_DIR/urls.txt) > $MONITOR_DIR/new-urls.txt
    
    # New JS files
    comm -13 <(sort $BASELINE/js.txt) <(sort $MONITOR_DIR/js.txt) > $MONITOR_DIR/new-js.txt
    
    # New documents
    comm -13 <(sort $BASELINE/docs.txt) <(sort $MONITOR_DIR/docs.txt) > $MONITOR_DIR/new-docs.txt
    
    # Report
    if [ -s $MONITOR_DIR/new-urls.txt ]; then
        echo "[!] ALERT: New URLs found!"
        echo "    New URLs: $(wc -l < $MONITOR_DIR/new-urls.txt)"
        echo "    New JS: $(wc -l < $MONITOR_DIR/new-js.txt)"
        echo "    New Docs: $(wc -l < $MONITOR_DIR/new-docs.txt)"
        
        # Could send notification here
        # mail -s "New URLs found on $TARGET" you@example.com < $MONITOR_DIR/new-urls.txt
    fi
else
    echo "[*] Creating baseline..."
    cp -r $MONITOR_DIR $BASELINE
fi
```

## Example 7: Multi-Target Batch Processing

```bash
#!/bin/bash
# Process multiple targets in parallel

TARGETS_FILE="targets.txt"
OUTPUT_DIR="batch-results"
CONCURRENCY=5

mkdir -p $OUTPUT_DIR

echo "[*] Processing $(wc -l < $TARGETS_FILE) targets with concurrency $CONCURRENCY"

# Function to process single target
process_target() {
    local target=$1
    local safe_name=$(echo $target | tr '.' '-')
    local target_dir="$OUTPUT_DIR/$safe_name"
    
    mkdir -p $target_dir
    
    echo "[*] Processing $target..."
    
    # Discovery + Crawl + Probe
    urlx -domain $target \
      -crawl \
      -depth 2 \
      -probe \
      -mc 200,403 \
      -only ".js,.json,.pdf" \
      -v \
      -o $target_dir/results.txt \
      2>&1 | tee $target_dir/log.txt
    
    echo "[+] Completed $target"
}

export -f process_target
export OUTPUT_DIR

# Process in parallel
cat $TARGETS_FILE | xargs -P $CONCURRENCY -I {} bash -c 'process_target "$@"' _ {}

echo "[+] Batch processing complete!"
echo "Results in: $OUTPUT_DIR/"
```

---

These examples demonstrate the full power of urlX combining:
- **Passive discovery** (11+ sources)
- **Active crawling** (HTML/JS parsing)
- **Live probing** (DNS, TCP, TLS, HTTP)
- **File filtering** (--only/--remove)
- **Technology detection**
- **Comprehensive reporting**
