package main

import (
	"bufio"
	"fmt"
	"os"
	"strings"
	"strconv"
	"sort"
)

type LogEntry struct {
	Action     string
	Protocol   string
	SourceIP   string
	DestIP     string
	SourcePort int
	DestPort   int
	Direction  string
}

func main() {
	file, err := os.Open("pfirewall.log")
	if err != nil {
		fmt.Println("Error opening file:", err)
		return
	}
	defer file.Close()

	// Counters
	actionCounts := map[string]int{}
	srcIPCounts := map[string]int{}
	dstPortCounts := map[int]int{}
	sendIPs := map[string]bool{}
	receiveIPs := map[string]bool{}

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) < 15 {
			continue
		}

		action := fields[2]
		protocol := fields[3]
		srcIP := fields[4]
		dstIP := fields[5]
		srcPort, _ := strconv.Atoi(fields[6])
		dstPort, _ := strconv.Atoi(fields[7])
		direction := fields[len(fields)-1]

		// Count actions
		actionCounts[action]++

		// Count source IPs
		srcIPCounts[srcIP]++

		// Count destination ports
		dstPortCounts[dstPort]++

		// Track direction
		if direction == "SEND" {
			sendIPs[srcIP] = true
		} else if direction == "RECEIVE" {
			receiveIPs[dstIP] = true
		}

		_ = protocol
		_ = srcPort
		_ = dstIP
	}

	// Output results
	fmt.Println("📊 Action counts:")
	for action, count := range actionCounts {
		fmt.Printf("   %s: %d\n", action, count)
	}

	// Top 5 source IPs
	fmt.Println("\n Top 5 most common source IPs:")
	printTopN(srcIPCounts, 5)

	// Top 5 destination ports
	fmt.Println("\n Top 5 destination ports:")
	printTopNInt(dstPortCounts, 5)

	// SEND IPs
	fmt.Println("\n List of IPs for SEND:")
	for ip := range sendIPs {
		fmt.Printf("   %s\n", ip)
	}
	fmt.Printf("   Total: %d IPs\n", len(sendIPs))

	// RECEIVE IPs
	fmt.Println("\n List of IPs for RECEIVE:")
	for ip := range receiveIPs {
		fmt.Printf("   %s\n", ip)
	}
	fmt.Printf("   Total: %d IPs\n", len(receiveIPs))

	// Suspicious ports
	suspicious := []int{22, 23, 445, 3389}
	fmt.Println("\n List of IPs/port ranges of concern:")
	for _, p := range suspicious {
		if c, ok := dstPortCounts[p]; ok {
			fmt.Printf("   Port %d: %d connections\n", p, c)
		}
	}
}

func printTopN(m map[string]int, n int) {
	type kv struct {
		Key   string
		Value int
	}
	var sorted []kv
	for k, v := range m {
		sorted = append(sorted, kv{k, v})
	}
	sort.Slice(sorted, func(i, j int) bool {
		return sorted[i].Value > sorted[j].Value
	})
	for i := 0; i < len(sorted) && i < n; i++ {
		fmt.Printf("   %s: %d connections\n", sorted[i].Key, sorted[i].Value)
	}
}

func printTopNInt(m map[int]int, n int) {
	type kv struct {
		Key   int
		Value int
	}
	var sorted []kv
	for k, v := range m {
		sorted = append(sorted, kv{k, v})
	}
	sort.Slice(sorted, func(i, j int) bool {
		return sorted[i].Value > sorted[j].Value
	})
	for i := 0; i < len(sorted) && i < n; i++ {
		fmt.Printf("   Port %d: %d connections\n", sorted[i].Key, sorted[i].Value)
	}
}