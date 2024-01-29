// main.go
package main

import (
	"flag"
	"log"
	analysis "p11i/ssh_log_analyzer/analysis"
	parsing "p11i/ssh_log_analyzer/parsing"
	"time"
)

func main() {
	// Command-line flags
	logFile := flag.String("log", "/var/log/auth.log", "Path to the log file")
	filterUser := flag.String("user", "", "Filter results by username")
	filterIP := flag.String("ip", "", "Filter results by IP address")
	timeRange := flag.Duration("time", 24*time.Hour, "Time range for analysis (e.g., 1h, 24h)")
	flag.Parse()

	// Parse SSH logs
	logEntries, err := parsing.ParseSSHLogs(*logFile)
	if err != nil {
		log.Fatal("Error parsing logs:", err)
	}

	// Filter results
	logEntries = analysis.FilterResults(logEntries, *filterUser, *filterIP, time.Now().Add(-*timeRange))

	// Analyze and print summary
	analysis.PrintSummary(logEntries)
}
