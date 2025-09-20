// Windows Defender Firewall Log Analyser (Go version)
// ---------------------------------------------------
// Parses Windows Firewall logs and produces a summary:
// - Action counts (ALLOW / DROP)
// - Top 5 source IPs
// - Top 5 destination ports
// - Lists of IPs for SEND and RECEIVE
// - Suspicious ports (445, 3389, 22, 23)
//
// Usage:
//   go run main.go
//   (then follow prompts for input/output files)

package main

import (
	"bufio"
	"fmt"
	"os"
	"sort"
	"strings"
	"time"
)

func main() {
	reader := bufio.NewReader(os.Stdin)

	fmt.Print("Enter path to firewall log file: ")
	logPath, _ := reader.ReadString('\n')
	logPath = strings.TrimSpace(logPath)
	if logPath == "" {
		logPath = "pfirewall.log"
	}

	fmt.Print("Enter path to save the output report (e.g., report.txt): ")
	outputPath, _ := reader.ReadString('\n')
	outputPath = strings.TrimSpace(outputPath)
	if outputPath == "" {
		outputPath = "report.txt"
	}

	actionCounter := make(map[string]int)
	srcIPCounter := make(map[string]int)
	dstPortCounter := make(map[string]int)
	sendIPs := make(map[string]bool)
	receiveIPs := make(map[string]bool)
	totalEntries := 0

	suspiciousPorts := map[string]bool{"445": true, "3389": true, "22": true, "23": true}

	file, err := os.Open(logPath)
	if err != nil {
		fmt.Printf("Log file not found: %s\n", logPath)
		return
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := scanner.Text()
		if strings.HasPrefix(line, "#") || strings.TrimSpace(line) == "" {
			continue
		}

		parts := strings.Fields(line)
		if len(parts) < 8 {
			continue
		}

		action := parts[2]
		srcIP := parts[4]
		dstPort := parts[7]

		actionCounter[action]++
		srcIPCounter[srcIP]++
		dstPortCounter[dstPort]++
		totalEntries++

		if strings.HasSuffix(line, "SEND") {
			sendIPs[srcIP] = true
		} else if strings.HasSuffix(line, "RECEIVE") {
			receiveIPs[parts[5]] = true
		}
	}

	var report []string

	report = append(report, "Action counts:")
	for k, v := range actionCounter {
		report = append(report, fmt.Sprintf("   %s: %d", k, v))
	}

	report = append(report, "\nTop 5 most common source IPs:")
	report = append(report, topN(srcIPCounter, 5)...)

	report = append(report, "\nTop 5 destination ports:")
	report = append(report, topN(dstPortCounter, 5)...)

	report = append(report, "\nList of IPs for SEND:")
	for ip := range sendIPs {
		report = append(report, "   "+ip)
	}
	report = append(report, fmt.Sprintf("   Total: %d IPs", len(sendIPs)))

	report = append(report, "\nList of IPs for RECEIVE:")
	for ip := range receiveIPs {
		report = append(report, "   "+ip)
	}
	report = append(report, fmt.Sprintf("   Total: %d IPs", len(receiveIPs)))

	report = append(report, "\nList of IPs/port ranges of concern:")
	flagged := false
	for port, count := range dstPortCounter {
		if suspiciousPorts[port] {
			report = append(report, fmt.Sprintf("   Port %s: %d connections", port, count))
			flagged = true
		}
	}
	if !flagged {
		report = append(report, "   None flagged")
	}

	// Add footer with timestamp and total entries
	now := time.Now().Format("2006-01-02 15:04:05")
	report = append(report, fmt.Sprintf("\n✅ Analysis complete: %d entries processed", totalEntries))
	report = append(report, fmt.Sprintf("Run on: %s", now))

	fmt.Println(strings.Join(report, "\n"))

	err = os.WriteFile(outputPath, []byte(strings.Join(report, "\n")), 0644)
	if err != nil {
		fmt.Printf("Could not write report: %v\n", err)
	} else {
		fmt.Printf("\nReport written to %s\n", outputPath)
	}
}

// topN returns the top N entries from a counter map as a slice of strings
func topN(counter map[string]int, n int) []string {
	type kv struct {
		Key   string
		Value int
	}

	var ss []kv
	for k, v := range counter {
		ss = append(ss, kv{k, v})
	}

	sort.Slice(ss, func(i, j int) bool {
		return ss[i].Value > ss[j].Value
	})

	var lines []string
	for i := 0; i < len(ss) && i < n; i++ {
		lines = append(lines, fmt.Sprintf("   %s: %d connections", ss[i].Key, ss[i].Value))
	}
	return lines
}