
package main

import (
	"archive/zip"
	"bufio"
	"bytes"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"
)


func init() {
	log.SetFlags(log.LstdFlags | log.Lshortfile)
}


var (
	headers = map[string]string{
		"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/58.0.3029.110 Safari/537.3",
	}
	currentDir    = getCurrentDir()
	asnURL        = "https://download.maxmind.com/app/geoip_download?edition_id=GeoLite2-ASN-CSV&license_key=%s&suffix=zip"
	sourceRepoURL = "https://github.com/blackmatrix7/ios_rule_script/archive/refs/heads/master.zip"
	readmeURL     = "https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/master/rule/Clash/README.md"
	asnV4         = make(map[int][]string)
	asnV6         = make(map[int][]string)
	ruleCategories = make(map[string][]string) 
)


type RuleSet struct {
	Version int    `json:"version"`
	Rules   []Rule `json:"rules"`
}

type Rule struct {
	Domain        []string `json:"domain,omitempty"`
	DomainKeyword []string `json:"domain_keyword,omitempty"`
	DomainSuffix  []string `json:"domain_suffix,omitempty"`
	IPCidr        []string `json:"ip_cidr,omitempty"`
	ProcessName   []string `json:"process_name,omitempty"`
}


func getCurrentDir() string {
	dir, err := os.Getwd()
	if err != nil {
		log.Fatal("Failed to get current directory:", err)
	}
	return dir
}


func checkSingBoxCommand() bool {
	
	cmd := exec.Command("sing-box", "version")
	var stdout bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stdout
	
	if err := cmd.Run(); err != nil {
		log.Printf("sing-box version check failed: %v", err)
		return false
	}
	
	
	cmd = exec.Command("sing-box", "rule-set", "--help")
	cmd.Stdout = &stdout
	cmd.Stderr = &stdout
	
	if err := cmd.Run(); err != nil {
		log.Printf("sing-box rule-set command check failed: %v", err)
		return false
	}
	
	log.Println("sing-box command is available")
	return true
}


func downloadFile(url string, filepath string) error {
	const maxRetries = 3
	const retryDelay = 5 * time.Second
	
	for attempt := 1; attempt <= maxRetries; attempt++ {
		log.Printf("Download attempt %d/%d for %s", attempt, maxRetries, filepath)
		
		err := downloadFileOnce(url, filepath)
		if err == nil {
			return nil
		}
		
		log.Printf("Download attempt %d failed: %v", attempt, err)
		
		if attempt < maxRetries {
			log.Printf("Retrying in %v...", retryDelay)
			time.Sleep(retryDelay)
		}
	}
	
	return fmt.Errorf("failed to download after %d attempts", maxRetries)
}


func downloadFileOnce(url string, filepath string) error {
	client := &http.Client{
		Timeout: 15 * time.Minute,
	}
	
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return err
	}
	
	
	for key, value := range headers {
		req.Header.Set(key, value)
	}
	
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("bad status: %s", resp.Status)
	}
	
	
	tempFile := filepath + ".tmp"
	out, err := os.Create(tempFile)
	if err != nil {
		return err
	}
	defer out.Close()
	
	
	buf := make([]byte, 32*1024)
	downloaded := int64(0)
	
	for {
		n, err := resp.Body.Read(buf)
		if n > 0 {
			if _, writeErr := out.Write(buf[:n]); writeErr != nil {
				os.Remove(tempFile)
				return writeErr
			}
			downloaded += int64(n)
			
			
			if downloaded%(10*1024*1024) == 0 {
				log.Printf("Downloaded %d MB", downloaded/(1024*1024))
			}
		}
		
		if err == io.EOF {
			break
		}
		if err != nil {
			os.Remove(tempFile)
			return err
		}
	}
	
	
	if err := out.Sync(); err != nil {
		os.Remove(tempFile)
		return err
	}
	
	
	out.Close()
	
	
	if err := os.Rename(tempFile, filepath); err != nil {
		os.Remove(tempFile)
		return err
	}
	
	log.Printf("Download completed: %s (%.2f MB)", filepath, float64(downloaded)/(1024*1024))
	return nil
}


func downloadAndParseREADME() error {
	readmeFile := filepath.Join(currentDir, "README.md")
	
	log.Println("Downloading README.md...")
	if err := downloadFile(readmeURL, readmeFile); err != nil {
		return fmt.Errorf("failed to download README.md: %v", err)
	}
	
	log.Println("Parsing README.md...")
	if err := parseREADME(readmeFile); err != nil {
		return fmt.Errorf("failed to parse README.md: %v", err)
	}
	
	
	os.Remove(readmeFile)
	
	return nil
}


func parseREADME(filename string) error {
	file, err := os.Open(filename)
	if err != nil {
		return err
	}
	defer file.Close()
	
	scanner := bufio.NewScanner(file)
	var currentCategory string
	
	
	rulePattern := regexp.MustCompile(`\[([^\]]+)\]\(https://github\.com/blackmatrix7/ios_rule_script/tree/master/rule/Clash/([^)]+)\)`)
	
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		
		
		if strings.HasPrefix(line, "|") && strings.Contains(line, "📵") {
			currentCategory = "Advertising"
		} else if strings.HasPrefix(line, "|") && strings.Contains(line, "🌏Global") {
			currentCategory = "Global"
		} else if strings.HasPrefix(line, "|") && strings.Contains(line, "🌏GlobalMedia") {
			currentCategory = "GlobalMedia"
		} else if strings.HasPrefix(line, "|") && strings.Contains(line, "🇨🇳Mainland") {
			currentCategory = "Mainland"
		} else if strings.HasPrefix(line, "|") && strings.Contains(line, "🇨🇳MainlandMedia") {
			currentCategory = "MainlandMedia"
		} else if strings.HasPrefix(line, "|") && strings.Contains(line, "📺Media") {
			currentCategory = "Media"
		} else if strings.HasPrefix(line, "|") && strings.Contains(line, "🎮Game") {
			currentCategory = "Game"
		} else if strings.HasPrefix(line, "|") && strings.Contains(line, "🍎Apple") {
			currentCategory = "Apple"
		} else if strings.HasPrefix(line, "|") && strings.Contains(line, "🗄️Microsoft") {
			currentCategory = "Microsoft"
		} else if strings.HasPrefix(line, "|") && strings.Contains(line, "📟Google") {
			currentCategory = "Google"
		} else if strings.HasPrefix(line, "|") && strings.Contains(line, "🚫Reject") {
			currentCategory = "Reject"
		} else if strings.HasPrefix(line, "|") && strings.Contains(line, "🖥️Other") {
			currentCategory = "Other"
		}
		
		
		if currentCategory != "" && strings.HasPrefix(line, "|") && !strings.Contains(line, "----") {
			matches := rulePattern.FindAllStringSubmatch(line, -1)
			for _, match := range matches {
				if len(match) >= 3 {
					ruleName := strings.TrimSpace(match[2])
					
					if strings.Contains(ruleName, "/") {
						parts := strings.Split(ruleName, "/")
						ruleName = parts[len(parts)-1] 
					}
					
					if ruleName != "" {
						ruleCategories[currentCategory] = append(ruleCategories[currentCategory], ruleName)
					}
				}
			}
		}
	}
	
	if err := scanner.Err(); err != nil {
		return err
	}
	
	
	log.Printf("Parsed %d categories from README.md:", len(ruleCategories))
	for category, rules := range ruleCategories {
		log.Printf("  %s: %d rules", category, len(rules))
	}
	
	return nil
}


func unzip(src, dest string) error {
	r, err := zip.OpenReader(src)
	if err != nil {
		return err
	}
	defer r.Close()
	
	
	os.MkdirAll(dest, 0755)
	
	
	for _, f := range r.File {
		func() {
			rc, err := f.Open()
			if err != nil {
				log.Printf("Failed to open file %s: %v", f.Name, err)
				return
			}
			defer rc.Close()
			
			path := filepath.Join(dest, f.Name)
			
			if f.FileInfo().IsDir() {
				os.MkdirAll(path, 0755)
				return
			}
			
			if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
				log.Printf("Failed to create directory %s: %v", filepath.Dir(path), err)
				return
			}
			
			outFile, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, f.Mode())
			if err != nil {
				log.Printf("Failed to create file %s: %v", path, err)
				return
			}
			defer outFile.Close()
			
			_, err = io.Copy(outFile, rc)
			if err != nil {
				log.Printf("Failed to copy file %s: %v", path, err)
				return
			}
		}()
	}
	
	return nil
}


func unzipWithSkipTopLevel(src, dest string) error {
	r, err := zip.OpenReader(src)
	if err != nil {
		return err
	}
	defer r.Close()
	
	os.MkdirAll(dest, 0755)
	
	var topLevelDir string
	for _, f := range r.File {
		if f.FileInfo().IsDir() && strings.Count(f.Name, "/") == 1 {
			topLevelDir = strings.TrimSuffix(f.Name, "/")
			break
		}
	}
	
	if topLevelDir == "" {
		return fmt.Errorf("no top level directory found")
	}
	
	log.Printf("Extracting files from top level directory: %s", topLevelDir)
	
	for _, f := range r.File {
		if !strings.HasPrefix(f.Name, topLevelDir+"/") {
			continue
		}
		
		relativePath := strings.TrimPrefix(f.Name, topLevelDir+"/")
		if relativePath == "" {
			continue
		}
		
		func() {
			rc, err := f.Open()
			if err != nil {
				log.Printf("Failed to open file %s: %v", f.Name, err)
				return
			}
			defer rc.Close()
			
			path := filepath.Join(dest, relativePath)
			
			if f.FileInfo().IsDir() {
				os.MkdirAll(path, 0755)
				return
			}
			
			if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
				log.Printf("Failed to create directory %s: %v", filepath.Dir(path), err)
				return
			}
			
			outFile, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, f.Mode())
			if err != nil {
				log.Printf("Failed to create file %s: %v", path, err)
				return
			}
			defer outFile.Close()
			
			_, err = io.Copy(outFile, rc)
			if err != nil {
				log.Printf("Failed to copy file %s: %v", path, err)
				return
			}
		}()
	}
	
	return nil
}


func findASNFiles(asnFolderPath string) (string, string, error) {
	var ipv4File, ipv6File string
	
	err := filepath.Walk(asnFolderPath, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		
		if !info.IsDir() && strings.HasSuffix(path, ".csv") {
			if strings.Contains(path, "IPv4") {
				ipv4File = path
			} else if strings.Contains(path, "IPv6") {
				ipv6File = path
			}
		}
		
		return nil
	})
	
	if err != nil {
		return "", "", err
	}
	
	if ipv4File == "" || ipv6File == "" {
		return "", "", fmt.Errorf("ASN CSV files not found - IPv4: %s, IPv6: %s", ipv4File, ipv6File)
	}
	
	return ipv4File, ipv6File, nil
}


func initialize() {
	
	dirPath := filepath.Join(currentDir, "rule")
	if _, err := os.Stat(dirPath); err == nil {
		log.Printf("%s exists, delete!", dirPath)
		os.RemoveAll(dirPath)
	}
	os.MkdirAll(dirPath, 0755)
	
	
	maxmindKey := os.Getenv("MAXMIND_KEY")
	if strings.TrimSpace(maxmindKey) == "" {
		log.Fatal("MAXMIND_KEY not set!")
	}
	
	log.Println("downloading asn file...")
	zipPath := filepath.Join(currentDir, "asn.zip")
	if err := downloadFile(fmt.Sprintf(asnURL, maxmindKey), zipPath); err != nil {
		log.Fatal("downloading asn file error:", err)
	}
	log.Println("downloading asn file complete")
	
	
	if info, err := os.Stat(zipPath); err != nil {
		log.Fatal("downloaded asn file not found:", err)
	} else {
		log.Printf("Downloaded ASN file size: %.2f MB", float64(info.Size())/(1024*1024))
	}
	
	
	asnFolderPath := filepath.Join(currentDir, "asn")
	if err := unzip(zipPath, asnFolderPath); err != nil {
		log.Fatal("unzip asn file error:", err)
	}
	log.Printf("unzip asn files to %s", asnFolderPath)
	
	
	asnV4File, asnV6File, err := findASNFiles(asnFolderPath)
	if err != nil {
		log.Printf("Warning: %v", err)
	} else {
		log.Printf("Found IPv4 ASN file: %s", asnV4File)
		log.Printf("Found IPv6 ASN file: %s", asnV6File)
		
		
		if err := processASNFile(asnV4File, asnV4); err != nil {
			log.Printf("Warning: process IPv4 ASN file error: %v", err)
		} else {
			log.Printf("Processed IPv4 ASN: %d entries", len(asnV4))
		}
		
		
		if err := processASNFile(asnV6File, asnV6); err != nil {
			log.Printf("Warning: process IPv6 ASN file error: %v", err)
		} else {
			log.Printf("Processed IPv6 ASN: %d entries", len(asnV6))
		}
	}
	
	log.Println("aggregating asn info finishes")
}


func processASNFile(filename string, asnMap map[int][]string) error {
	file, err := os.Open(filename)
	if err != nil {
		return err
	}
	defer file.Close()
	
	reader := csv.NewReader(file)
	
	
	if _, err := reader.Read(); err != nil {
		return err
	}
	
	lineCount := 0
	for {
		row, err := reader.Read()
		if err == io.EOF {
			break
		}
		if err != nil {
			return err
		}
		
		lineCount++
		if len(row) < 2 {
			continue
		}
		
		asn, err := strconv.Atoi(row[1])
		if err != nil {
			log.Printf("Invalid ASN number on line %d: %s", lineCount, row[1])
			continue
		}
		
		asnMap[asn] = append(asnMap[asn], row[0])
	}
	
	log.Printf("Processed %d lines from %s", lineCount, filename)
	return nil
}


func downloadSourceRepo() {
	log.Println("downloading rule source file...")
	sourceZip := filepath.Join(currentDir, "ios_rule_script.zip")
	if err := downloadFile(sourceRepoURL, sourceZip); err != nil {
		log.Fatal("downloading rule source error:", err)
	}
	log.Println("downloading rule source complete")
	
	
	if info, err := os.Stat(sourceZip); err != nil {
		log.Fatal("downloaded rule source file not found:", err)
	} else {
		log.Printf("Downloaded rule source file size: %.2f MB", float64(info.Size())/(1024*1024))
	}
	
	sourceFolder := filepath.Join(currentDir, "ios_rule_script")
	log.Println("Starting extraction of rule source files...")
	if err := unzipWithSkipTopLevel(sourceZip, sourceFolder); err != nil {
		log.Fatal("unzip rule source error:", err)
	}
	log.Printf("unzip rule source files to %s", sourceFolder)
}


func createRuleSet(domain, domainKeyword, domainSuffix, ipCidr, processName []string) *RuleSet {
	rs := &RuleSet{
		Version: 2,
		Rules:   []Rule{},
	}
	
	
	domain = removeDuplicates(domain)
	domainKeyword = removeDuplicates(domainKeyword)
	domainSuffix = removeDuplicates(domainSuffix)
	ipCidr = removeDuplicates(ipCidr)
	processName = removeDuplicates(processName)
	
	
	if len(domain) > 0 || len(domainKeyword) > 0 || len(domainSuffix) > 0 || len(ipCidr) > 0 {
		rule := Rule{}
		if len(domain) > 0 {
			rule.Domain = domain
		}
		if len(domainKeyword) > 0 {
			rule.DomainKeyword = domainKeyword
		}
		if len(domainSuffix) > 0 {
			rule.DomainSuffix = domainSuffix
		}
		if len(ipCidr) > 0 {
			rule.IPCidr = ipCidr
		}
		rs.Rules = append(rs.Rules, rule)
	}
	
	
	if len(processName) > 0 {
		rule := Rule{
			ProcessName: processName,
		}
		rs.Rules = append(rs.Rules, rule)
	}
	
	return rs
}


func removeDuplicates(slice []string) []string {
	keys := make(map[string]bool)
	result := []string{}
	
	for _, item := range slice {
		if !keys[item] {
			keys[item] = true
			result = append(result, item)
		}
	}
	
	return result
}


func mergeRuleSets(ruleSets []*RuleSet) *RuleSet {
	if len(ruleSets) == 0 {
		return &RuleSet{Version: 2, Rules: []Rule{}}
	}
	
	var allDomains, allDomainKeywords, allDomainSuffixes, allIPCidrs, allProcessNames []string
	
	for _, rs := range ruleSets {
		for _, rule := range rs.Rules {
			allDomains = append(allDomains, rule.Domain...)
			allDomainKeywords = append(allDomainKeywords, rule.DomainKeyword...)
			allDomainSuffixes = append(allDomainSuffixes, rule.DomainSuffix...)
			allIPCidrs = append(allIPCidrs, rule.IPCidr...)
			allProcessNames = append(allProcessNames, rule.ProcessName...)
		}
	}
	
	return createRuleSet(allDomains, allDomainKeywords, allDomainSuffixes, allIPCidrs, allProcessNames)
}


func processRuleFile(sourceFile string) (*RuleSet, error) {
	var domain, domainKeyword, domainSuffix, ipCidr, processName []string
	
	file, err := os.Open(sourceFile)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	
	scanner := bufio.NewScanner(file)
	foundPayload := false
	
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		
		if strings.Contains(line, "payload:") {
			foundPayload = true
			continue
		}
		
		if !foundPayload {
			continue
		}
		
		
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		
		
		if !strings.HasPrefix(line, "- ") {
			continue
		}
		
		
		parts := strings.Split(line[2:], ",")
		if len(parts) < 2 {
			continue
		}
		
		ruleType := strings.TrimSpace(parts[0])
		ruleContent := strings.TrimSpace(parts[1])
		
		switch ruleType {
		case "DOMAIN":
			domain = append(domain, ruleContent)
		case "DOMAIN-SUFFIX":
			domainSuffix = append(domainSuffix, ruleContent)
		case "DOMAIN-KEYWORD":
			domainKeyword = append(domainKeyword, ruleContent)
		case "IP-CIDR", "IP-CIDR6":
			ipCidr = append(ipCidr, ruleContent)
		case "IP-ASN":
			asnNum, err := strconv.Atoi(ruleContent)
			if err != nil {
				log.Printf("Invalid ASN number in %s: %s", sourceFile, ruleContent)
				continue
			}
			ipCidr = append(ipCidr, asnV4[asnNum]...)
			ipCidr = append(ipCidr, asnV6[asnNum]...)
		case "PROCESS-NAME":
			processName = append(processName, ruleContent)
		}
	}
	
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	
	return createRuleSet(domain, domainKeyword, domainSuffix, ipCidr, processName), nil
}


func translateRulesByCategory() {
	sourceFolder := filepath.Join(currentDir, "ios_rule_script", "rule", "Clash")
	targetFolder := filepath.Join(currentDir, "rule")
	
	if _, err := os.Stat(sourceFolder); os.IsNotExist(err) {
		log.Fatalf("Source Clash rules folder not found: %s", sourceFolder)
	}
	
	processedCount := 0
	
	
	for category, ruleNames := range ruleCategories {
		log.Printf("Processing category: %s (%d rules)", category, len(ruleNames))
		
		var categoryRuleSets []*RuleSet
		validRuleCount := 0
		
		
		for _, ruleName := range ruleNames {
			
			sourceFile := findRuleFile(sourceFolder, ruleName)
			if sourceFile == "" {
				log.Printf("Rule file not found for: %s", ruleName)
				continue
			}
			
			
			ruleSet, err := processRuleFile(sourceFile)
			if err != nil {
				log.Printf("Failed to process rule file %s: %v", sourceFile, err)
				continue
			}
			
			categoryRuleSets = append(categoryRuleSets, ruleSet)
			validRuleCount++
		}
		
		if validRuleCount == 0 {
			log.Printf("No valid rules found for category: %s", category)
			continue
		}
		
		
		mergedRuleSet := mergeRuleSets(categoryRuleSets)
		
		
		categoryDir := filepath.Join(targetFolder, category)
		if err := os.MkdirAll(categoryDir, 0755); err != nil {
			log.Printf("Failed to create category directory %s: %v", categoryDir, err)
			continue
		}
		
		
		targetFile := filepath.Join(categoryDir, category+".json")
		jsonData, err := json.MarshalIndent(mergedRuleSet, "", "  ")
		if err != nil {
			log.Printf("Failed to marshal JSON for category %s: %v", category, err)
			continue
		}
		
		if err := os.WriteFile(targetFile, jsonData, 0644); err != nil {
			log.Printf("Failed to write JSON file %s: %v", targetFile, err)
			continue
		}

func findRuleFile(sourceFolder, ruleName string) string {
	
	possiblePaths := []string{
		filepath.Join(sourceFolder, ruleName, ruleName+".yaml"),
		filepath.Join(sourceFolder, ruleName, ruleName+"_Classical.yaml"),
		filepath.Join(sourceFolder, "Game", ruleName, ruleName+".yaml"),
		filepath.Join(sourceFolder, "Game", ruleName, ruleName+"_Classical.yaml"),
		filepath.Join(sourceFolder, "Cloud", ruleName, ruleName+".yaml"),
		filepath.Join(sourceFolder, "Cloud", ruleName, ruleName+"_Classical.yaml"),
	}
	
	for _, path := range possiblePaths {
		if _, err := os.Stat(path); err == nil {
			return path
		}
	}
	
	return ""
}


func compileSRSFiles() {
	if !checkSingBoxCommand() {
		log.Println("Warning: sing-box command not found or rule-set command not available")
		log.Println("To compile SRS files, please install sing-box and ensure it's in your PATH")
		return
	}
	
	log.Println("Starting SRS compilation...")
	
	ruleDir := filepath.Join(currentDir, "rule")
	compiledCount := 0
	failedCount := 0
	
	
	entries, err := os.ReadDir(ruleDir)
	if err != nil {
		log.Printf("Failed to read rule directory: %v", err)
		return
	}
	
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		
		categoryName := entry.Name()
		categoryDir := filepath.Join(ruleDir, categoryName)
		
		
		jsonFile := filepath.Join(categoryDir, categoryName+".json")
		
		
		if _, err := os.Stat(jsonFile); os.IsNotExist(err) {
			log.Printf("JSON file not found: %s", jsonFile)
			continue
		}
		
		
		srsFile := filepath.Join(categoryDir, categoryName+".srs")
		
		
		cmd := exec.Command("sing-box", "rule-set", "compile", "--output", srsFile, jsonFile)
		
		
		cmd.Dir = currentDir
		
		
		var stdout, stderr bytes.Buffer
		cmd.Stdout = &stdout
		cmd.Stderr = &stderr
		
		
		if err := cmd.Run(); err != nil {
			log.Printf("Failed to compile %s: %v", jsonFile, err)
			if stderr.Len() > 0 {
				log.Printf("Error output: %s", stderr.String())
			}
			failedCount++
			continue
		}
		
		log.Printf("Compiled: %s -> %s", jsonFile, srsFile)
		compiledCount++
	}
	
	log.Printf("SRS compilation completed: %d successful, %d failed", compiledCount, failedCount)
}


func postClean() {
	
	toRemove := []string{
		filepath.Join(currentDir, "asn"),
		filepath.Join(currentDir, "ios_rule_script"),
		filepath.Join(currentDir, "asn.zip"),
		filepath.Join(currentDir, "ios_rule_script.zip"),
	}
	
	for _, path := range toRemove {
		if _, err := os.Stat(path); err == nil {
			if err := os.RemoveAll(path); err != nil {
				log.Printf("Failed to remove %s: %v", path, err)
			} else {
				log.Printf("Removed: %s", path)
			}
		}
	}
	
	log.Println("Post-cleaning complete.")
}


func main() {
	log.Println("Starting rule conversion process...")
	
	
	if err := downloadAndParseREADME(); err != nil {
		log.Fatal("Failed to download and parse README.md:", err)
	}
	
	initialize()
downloadSourceRepo()
	translateRulesByCategory()
	
	
	compileSRSFiles()
	
	postClean()
	
	log.Println("Rule conversion completed successfully!")
}
