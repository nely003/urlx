package main

import (
	"bufio"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"
)

const banner = `
                             
                             
██  ██ █████▄  ██     ██  ██ 
██  ██ ██▄▄██▄ ██      ████  
▀████▀ ██   ██ ██████ ██  ██ 
                             
   URL Discovery By tool @alhamrizvii
    ================================
`

type URLSource interface {
	Fetch(domain string) ([]string, error)
	Name() string
}

// Wayback Machine
type WaybackMachine struct {
	client *http.Client
}

func (w *WaybackMachine) Name() string {
	return "Wayback Machine"
}

func (w *WaybackMachine) Fetch(domain string) ([]string, error) {
	apiURL := fmt.Sprintf("http://web.archive.org/cdx/search/cdx?url=*.%s/*&output=json&collapse=urlkey", domain)
	resp, err := w.client.Get(apiURL)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("status code: %d", resp.StatusCode)
	}

	var results [][]string
	if err := json.NewDecoder(resp.Body).Decode(&results); err != nil {
		return nil, err
	}

	urls := make([]string, 0)
	for i, record := range results {
		if i == 0 {
			continue
		}
		if len(record) > 2 {
			urls = append(urls, record[2])
		}
	}
	return urls, nil
}

// Archive.today
type ArchiveToday struct {
	client *http.Client
}

func (a *ArchiveToday) Name() string {
	return "Archive.today"
}

func (a *ArchiveToday) Fetch(domain string) ([]string, error) {
	apiURL := fmt.Sprintf("https://archive.ph/newest/%s", domain)
	resp, err := a.client.Get(apiURL)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	content := string(body)
	
	urls := make([]string, 0)
	lines := strings.Split(content, "\n")
	for _, line := range lines {
		if strings.Contains(line, "http") && strings.Contains(line, domain) {
			if u := extractURL(line); u != "" && strings.Contains(u, domain) {
				urls = append(urls, u)
			}
		}
	}
	return urls, nil
}

// Common Crawl
type CommonCrawl struct {
	client *http.Client
}

func (c *CommonCrawl) Name() string {
	return "Common Crawl"
}

func (c *CommonCrawl) Fetch(domain string) ([]string, error) {
	apiURL := fmt.Sprintf("http://index.commoncrawl.org/CC-MAIN-2024-10-index?url=*.%s&output=json", domain)
	resp, err := c.client.Get(apiURL)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	urls := make([]string, 0)
	scanner := bufio.NewScanner(resp.Body)
	for scanner.Scan() {
		var record map[string]interface{}
		if err := json.Unmarshal(scanner.Bytes(), &record); err != nil {
			continue
		}
		if urlStr, ok := record["url"].(string); ok {
			urls = append(urls, urlStr)
		}
	}
	return urls, scanner.Err()
}

// URLScan.io
type URLScan struct {
	client *http.Client
	apiKey string
}

func (u *URLScan) Name() string {
	return "URLScan.io"
}

func (u *URLScan) Fetch(domain string) ([]string, error) {
	apiURL := fmt.Sprintf("https://urlscan.io/api/v1/search/?q=domain:%s", domain)
	req, err := http.NewRequest("GET", apiURL, nil)
	if err != nil {
		return nil, err
	}
	if u.apiKey != "" {
		req.Header.Set("API-Key", u.apiKey)
	}

	resp, err := u.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var result struct {
		Results []struct {
			Page struct {
				URL string `json:"url"`
			} `json:"page"`
		} `json:"results"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, err
	}

	urls := make([]string, 0)
	for _, r := range result.Results {
		urls = append(urls, r.Page.URL)
	}
	return urls, nil
}

// AlienVault OTX
type AlienVaultOTX struct {
	client *http.Client
	apiKey string
}

func (a *AlienVaultOTX) Name() string {
	return "AlienVault OTX"
}

func (a *AlienVaultOTX) Fetch(domain string) ([]string, error) {
	apiURL := fmt.Sprintf("https://otx.alienvault.com/api/v1/indicators/domain/%s/url_list", domain)
	req, err := http.NewRequest("GET", apiURL, nil)
	if err != nil {
		return nil, err
	}
	if a.apiKey != "" {
		req.Header.Set("X-OTX-API-KEY", a.apiKey)
	}

	resp, err := a.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var result struct {
		URLList []struct {
			URL string `json:"url"`
		} `json:"url_list"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, err
	}

	urls := make([]string, 0)
	for _, u := range result.URLList {
		urls = append(urls, u.URL)
	}
	return urls, nil
}

// crt.sh (Certificate Transparency)
type CrtSh struct {
	client *http.Client
}

func (c *CrtSh) Name() string {
	return "crt.sh"
}

func (c *CrtSh) Fetch(domain string) ([]string, error) {
	apiURL := fmt.Sprintf("https://crt.sh/?q=%%25.%s&output=json", domain)
	resp, err := c.client.Get(apiURL)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var results []struct {
		NameValue string `json:"name_value"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&results); err != nil {
		return nil, err
	}

	urls := make([]string, 0)
	seen := make(map[string]bool)
	for _, r := range results {
		subdomains := strings.Split(r.NameValue, "\n")
		for _, sub := range subdomains {
			sub = strings.TrimSpace(sub)
			if sub != "" && !seen[sub] {
				urls = append(urls, "https://"+sub)
				seen[sub] = true
			}
		}
	}
	return urls, nil
}

// VirusTotal
type VirusTotal struct {
	client *http.Client
	apiKey string
}

func (v *VirusTotal) Name() string {
	return "VirusTotal"
}

func (v *VirusTotal) Fetch(domain string) ([]string, error) {
	if v.apiKey == "" {
		return nil, fmt.Errorf("API key required")
	}

	apiURL := fmt.Sprintf("https://www.virustotal.com/api/v3/domains/%s/urls", domain)
	req, err := http.NewRequest("GET", apiURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("x-apikey", v.apiKey)

	resp, err := v.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var result struct {
		Data []struct {
			Attributes struct {
				URL string `json:"url"`
			} `json:"attributes"`
		} `json:"data"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, err
	}

	urls := make([]string, 0)
	for _, item := range result.Data {
		urls = append(urls, item.Attributes.URL)
	}
	return urls, nil
}

// SecurityTrails
type SecurityTrails struct {
	client *http.Client
	apiKey string
}

func (s *SecurityTrails) Name() string {
	return "SecurityTrails"
}

func (s *SecurityTrails) Fetch(domain string) ([]string, error) {
	if s.apiKey == "" {
		return nil, fmt.Errorf("API key required")
	}

	apiURL := fmt.Sprintf("https://api.securitytrails.com/v1/domain/%s/subdomains", domain)
	req, err := http.NewRequest("GET", apiURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("APIKEY", s.apiKey)

	resp, err := s.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var result struct {
		Subdomains []string `json:"subdomains"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, err
	}

	urls := make([]string, 0)
	for _, sub := range result.Subdomains {
		urls = append(urls, fmt.Sprintf("https://%s.%s", sub, domain))
	}
	return urls, nil
}

// GitHub Code Search
type GitHub struct {
	client *http.Client
	apiKey string
}

func (g *GitHub) Name() string {
	return "GitHub"
}

func (g *GitHub) Fetch(domain string) ([]string, error) {
	query := url.QueryEscape(fmt.Sprintf("%s extension:json OR extension:txt OR extension:config", domain))
	apiURL := fmt.Sprintf("https://api.github.com/search/code?q=%s&per_page=100", query)
	
	req, err := http.NewRequest("GET", apiURL, nil)
	if err != nil {
		return nil, err
	}
	if g.apiKey != "" {
		req.Header.Set("Authorization", "token "+g.apiKey)
	}
	req.Header.Set("Accept", "application/vnd.github.v3+json")

	resp, err := g.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var result struct {
		Items []struct {
			HTMLURL string `json:"html_url"`
		} `json:"items"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, err
	}

	urls := make([]string, 0)
	for _, item := range result.Items {
		urls = append(urls, item.HTMLURL)
	}
	return urls, nil
}

// ThreatCrowd
type ThreatCrowd struct {
	client *http.Client
}

func (t *ThreatCrowd) Name() string {
	return "ThreatCrowd"
}

func (t *ThreatCrowd) Fetch(domain string) ([]string, error) {
	apiURL := fmt.Sprintf("https://www.threatcrowd.org/searchApi/v2/domain/report/?domain=%s", domain)
	resp, err := t.client.Get(apiURL)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var result struct {
		Subdomains []string `json:"subdomains"`
		Resolutions []struct {
			IP string `json:"ip_address"`
		} `json:"resolutions"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, err
	}

	urls := make([]string, 0)
	for _, sub := range result.Subdomains {
		urls = append(urls, "https://"+sub)
	}
	return urls, nil
}

// Censys
type Censys struct {
	client *http.Client
	apiID  string
	apiSecret string
}

func (c *Censys) Name() string {
	return "Censys"
}

func (c *Censys) Fetch(domain string) ([]string, error) {
	if c.apiID == "" || c.apiSecret == "" {
		return nil, fmt.Errorf("API credentials required")
	}

	apiURL := "https://search.censys.io/api/v2/certificates/search"
	query := fmt.Sprintf("names: %s", domain)
	
	reqBody := strings.NewReader(fmt.Sprintf(`{"q":"%s","per_page":100}`, query))
	req, err := http.NewRequest("POST", apiURL, reqBody)
	if err != nil {
		return nil, err
	}
	req.SetBasicAuth(c.apiID, c.apiSecret)
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var result struct {
		Result struct {
			Hits []struct {
				Names []string `json:"names"`
			} `json:"hits"`
		} `json:"result"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, err
	}

	urls := make([]string, 0)
	seen := make(map[string]bool)
	for _, hit := range result.Result.Hits {
		for _, name := range hit.Names {
			if !seen[name] && strings.Contains(name, domain) {
				urls = append(urls, "https://"+name)
				seen[name] = true
			}
		}
	}
	return urls, nil
}

// Helper function to extract URLs from text
func extractURL(text string) string {
	words := strings.Fields(text)
	for _, word := range words {
		if strings.HasPrefix(word, "http") {
			return strings.Trim(word, `"'<>()[]{}`)
		}
	}
	return ""
}

// URLCollector manages fetching from multiple sources
type URLCollector struct {
	sources []URLSource
	verbose bool
}

func NewURLCollector(verbose bool, config map[string]string) *URLCollector {
	client := &http.Client{
		Timeout: 30 * time.Second,
	}

	sources := []URLSource{
		&WaybackMachine{client: client},
		&ArchiveToday{client: client},
		&CommonCrawl{client: client},
		&URLScan{client: client, apiKey: config["urlscan"]},
		&AlienVaultOTX{client: client, apiKey: config["otx"]},
		&CrtSh{client: client},
		&ThreatCrowd{client: client},
	}

	// Add sources that require API keys only if provided
	if config["virustotal"] != "" {
		sources = append(sources, &VirusTotal{client: client, apiKey: config["virustotal"]})
	}
	if config["securitytrails"] != "" {
		sources = append(sources, &SecurityTrails{client: client, apiKey: config["securitytrails"]})
	}
	if config["github"] != "" {
		sources = append(sources, &GitHub{client: client, apiKey: config["github"]})
	}
	if config["censys_id"] != "" && config["censys_secret"] != "" {
		sources = append(sources, &Censys{
			client: client,
			apiID: config["censys_id"],
			apiSecret: config["censys_secret"],
		})
	}

	return &URLCollector{
		sources: sources,
		verbose: verbose,
	}
}

func (uc *URLCollector) FetchURLs(domain string) []string {
	var wg sync.WaitGroup
	urlChan := make(chan string, 1000)
	uniqueURLs := make(map[string]bool)
	var mu sync.Mutex

	for _, source := range uc.sources {
		wg.Add(1)
		go func(s URLSource) {
			defer wg.Done()

			if uc.verbose {
				fmt.Fprintf(os.Stderr, "[*] Fetching from %s for %s...\n", s.Name(), domain)
			}

			urls, err := s.Fetch(domain)
			if err != nil {
				if uc.verbose {
					fmt.Fprintf(os.Stderr, "[!] Error from %s: %v\n", s.Name(), err)
				}
				return
			}

			if uc.verbose {
				fmt.Fprintf(os.Stderr, "[+] Found %d URLs from %s\n", len(urls), s.Name())
			}

			for _, u := range urls {
				urlChan <- u
			}
		}(source)
	}

	go func() {
		wg.Wait()
		close(urlChan)
	}()

	for u := range urlChan {
		mu.Lock()
		if !uniqueURLs[u] {
			uniqueURLs[u] = true
		}
		mu.Unlock()
	}

	result := make([]string, 0, len(uniqueURLs))
	for u := range uniqueURLs {
		result = append(result, u)
	}
	return result
}

func readDomains(filename string) ([]string, error) {
	file, err := os.Open(filename)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	domains := make([]string, 0)
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		domain := strings.TrimSpace(scanner.Text())
		if domain != "" && !strings.HasPrefix(domain, "#") {
			if strings.Contains(domain, "://") {
				if u, err := url.Parse(domain); err == nil {
					domain = u.Hostname()
				}
			}
			domains = append(domains, domain)
		}
	}
	return domains, scanner.Err()
}

func main() {
	var (
		domainFile      = flag.String("d", "", "File containing domains/subdomains")
		domain          = flag.String("domain", "", "Single domain to query")
		output          = flag.String("o", "", "Output file (default: stdout)")
		verbose         = flag.Bool("v", false, "Verbose output")
		concurrency     = flag.Int("c", 5, "Concurrency level")
		urlscanKey      = flag.String("urlscan-key", "", "URLScan.io API key")
		otxKey          = flag.String("otx-key", "", "AlienVault OTX API key")
		vtKey           = flag.String("vt-key", "", "VirusTotal API key")
		sectrailsKey    = flag.String("securitytrails-key", "", "SecurityTrails API key")
		githubKey       = flag.String("github-key", "", "GitHub API token")
		censysID        = flag.String("censys-id", "", "Censys API ID")
		censysSecret    = flag.String("censys-secret", "", "Censys API Secret")
		noBanner        = flag.Bool("no-banner", false, "Disable banner")
	)

	flag.Parse()

	if !*noBanner {
		fmt.Fprint(os.Stderr, banner)
	}

	if *domainFile == "" && *domain == "" {
		fmt.Fprintln(os.Stderr, "Error: Provide -d (domain file) or -domain (single domain)")
		flag.Usage()
		os.Exit(1)
	}

	config := map[string]string{
		"urlscan":        *urlscanKey,
		"otx":            *otxKey,
		"virustotal":     *vtKey,
		"securitytrails": *sectrailsKey,
		"github":         *githubKey,
		"censys_id":      *censysID,
		"censys_secret":  *censysSecret,
	}

	collector := NewURLCollector(*verbose, config)

	var domains []string
	if *domain != "" {
		domains = []string{*domain}
	} else {
		var err error
		domains, err = readDomains(*domainFile)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error reading domain file: %v\n", err)
			os.Exit(1)
		}
	}

	if *verbose {
		fmt.Fprintf(os.Stderr, "[*] Loaded %d domains\n", len(domains))
		fmt.Fprintf(os.Stderr, "[*] Active sources: %d\n\n", len(collector.sources))
	}

	var writer io.Writer = os.Stdout
	if *output != "" {
		f, err := os.Create(*output)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error creating output file: %v\n", err)
			os.Exit(1)
		}
		defer f.Close()
		writer = f
	}

	domainChan := make(chan string, len(domains))
	for _, d := range domains {
		domainChan <- d
	}
	close(domainChan)

	var wg sync.WaitGroup
	var mu sync.Mutex
	allURLs := make(map[string]bool)

	for i := 0; i < *concurrency; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for domain := range domainChan {
				urls := collector.FetchURLs(domain)
				mu.Lock()
				for _, u := range urls {
					allURLs[u] = true
				}
				mu.Unlock()
			}
		}()
	}

	wg.Wait()

	for u := range allURLs {
		fmt.Fprintln(writer, u)
	}

	if *verbose {
		fmt.Fprintf(os.Stderr, "\n[+] Total unique URLs found: %d\n", len(allURLs))
	}
}
