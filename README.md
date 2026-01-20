<img width="748" height="310" alt="image" src="https://github.com/user-attachments/assets/08dc9c98-5a81-439d-8b94-3ba7d85fa7a1" />

# urlX — Multi‑Source URL Discovery Tool

[![Go Version](https://img.shields.io/badge/Go-1.19%2B-00ADD8?style=flat\&logo=go)](https://golang.org)
[![Stars](https://img.shields.io/github/stars/alhamrizvi-cloud/urlx?style=flat)](https://github.com/alhamrizvi-cloud/urlx/stargazers)
[![Forks](https://img.shields.io/github/forks/alhamrizvi-cloud/urlx?style=flat)](https://github.com/alhamrizvi-cloud/urlx/network)
[![Issues](https://img.shields.io/github/issues/alhamrizvi-cloud/urlx)](https://github.com/alhamrizvi-cloud/urlx/issues)
[![Last Commit](https://img.shields.io/github/last-commit/alhamrizvi-cloud/urlx)](https://github.com/alhamrizvi-cloud/urlx/commits/main)
[![Code Size](https://img.shields.io/github/languages/code-size/alhamrizvi-cloud/urlx)](https://github.com/alhamrizvi-cloud/urlx)
[![Top Language](https://img.shields.io/github/languages/top/alhamrizvi-cloud/urlx)](https://github.com/alhamrizvi-cloud/urlx)

**urlX** is a fast, extensible reconnaissance tool that aggregates URLs from **archives, certificate transparency logs, threat‑intel platforms, and code repositories**.

Built for **bug bounty hunters**, **pentesters**, and **security researchers** who want **maximum URL coverage** with **minimal effort**.

## ✨ Key Features

* 🔎 **11+ Data Sources** for deep URL discovery
* ⚡ **Concurrent fetching** with configurable workers
* 🧠 **Smart deduplication** across all sources
* 📥 **Flexible input** — single domain or domain lists
* 🔐 **Optional API keys** for enhanced coverage
* 📤 **Stdout or file output** (tool‑chain friendly)
* 🐞 **Verbose mode** for debugging & research

## 📡 Data Sources

### 🕰️ Historical & Archive

* Wayback Machine (archive.org)
* Archive.today (archive.is)
* Common Crawl

### 🔐 Certificate Intelligence

* crt.sh (Certificate Transparency)
* Censys

### 🧠 Threat Intelligence

* AlienVault OTX
* VirusTotal
* ThreatCrowd

### 🌐 Security Platforms

* URLScan.io
* SecurityTrails

### 🧑‍💻 Code & Secrets

* GitHub (endpoint & URL discovery in public code)


## 🚀 Installation

### ✅ Using `go install` (Recommended)

```bash
GOPROXY=direct go install github.com/alhamrizvi-cloud/urlx@latest
```

Make sure `$GOPATH/bin` is in your `$PATH`.

### 🛠️ Build from Source

```bash
git clone https://github.com/alhamrizvi-cloud/urlx.git
cd urlx
go build -o urlx main.go
```

## 📖 Usage

### 🔹 Single Domain

```bash
urlx -domain example.com
```

### 🔹 Multiple Domains (File)

```bash
urlx -d domains.txt
```

### 🔹 Save Output

```bash
urlx -d domains.txt -o urls.txt
```

### 🔹 Verbose Mode

```bash
urlx -domain example.com -v
```
## ⚙️ Advanced Usage

### With API Keys (Maximum Coverage)

```bash
urlx -d subs.txt \
  -urlscan-key YOUR_KEY \
  -otx-key YOUR_KEY \
  -vt-key YOUR_KEY \
  -securitytrails-key YOUR_KEY \
  -github-key YOUR_KEY \
  -censys-id YOUR_ID \
  -censys-secret YOUR_SECRET \
  -o results.txt -v
```

### Increase Concurrency

```bash
urlx -d domains.txt -c 20
```

## 🧰 Tool Chaining Examples

### Bug Bounty Workflow

```bash
subfinder -d target.com -silent > subs.txt
urlx -d subs.txt -o urls.txt
httpx -l urls.txt -silent > live.txt
nuclei -l live.txt
```

### FFUF

```bash
urlx -domain target.com | ffuf -w - -u FUZZ
```

### Parameter Discovery

```bash
urlx -domain target.com | unfurl keys | sort -u
```
## 🏷️ Flags

| Flag                  | Description       |
| --------------------- | ----------------- |
| `-d`                  | File with domains |
| `-domain`             | Single domain     |
| `-o`                  | Output file       |
| `-v`                  | Verbose           |
| `-c`                  | Concurrency       |
| `-no-banner`          | Disable banner    |
| `-urlscan-key`        | URLScan API       |
| `-otx-key`            | AlienVault OTX    |
| `-vt-key`             | VirusTotal        |
| `-securitytrails-key` | SecurityTrails    |
| `-github-key`         | GitHub Token      |
| `-censys-id`          | Censys ID         |
| `-censys-secret`      | Censys Secret     |

## 🔑 API Notes

* Most sources work **without keys**
* API keys = **more URLs + higher rate limits**
* Free tiers supported where available

## ⚠️ Disclaimer

This tool is for **authorized security testing and research only**.
You are responsible for complying with laws and program rules.

## 🤝 Contributing

Pull requests are welcome.

To add a new source, implement:

```go
type URLSource interface {
  Fetch(domain string) ([]string, error)
  Name() string
}
```

## ⭐ Support

If this project helps you:

* ⭐ Star the repo
* 🐛 Report issues
* 🔧 Submit PRs

**Happy Hunting 🎯**
