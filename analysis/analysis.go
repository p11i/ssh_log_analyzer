// analysis/analysis.go

package analysis

import (
	"fmt"
	"strings"
	"time"

	parsing "p11i/ssh_log_analyzer/parsing"
)

func FilterResults(logEntries []parsing.LogEntry, filterUser, filterIP string, timeThreshold time.Time) []parsing.LogEntry {
	var filteredEntries []parsing.LogEntry
	for _, entry := range logEntries {
		if (filterUser == "" || entry.Username == filterUser) &&
			(filterIP == "" || entry.IPAddress == filterIP) &&
			entry.Time.After(timeThreshold) {
			filteredEntries = append(filteredEntries, entry)
		}
	}
	return filteredEntries
}

func PrintSummary(logEntries []parsing.LogEntry) {
	fmt.Printf("%-20s%-15s%-15s%-15s\n", "Time", "IP Address", "Username", "Attempt Type")
	fmt.Println(strings.Repeat("-", 65))

	failedAttempts := make(map[parsing.LogEntry]int)
	for _, entry := range logEntries {
		failedAttempts[entry]++
	}

	for attempt := range failedAttempts {
		fmt.Printf("%-20s%-15s%-15s%-15s\n", attempt.Time.Format("Jan 02 15:04:05"), attempt.IPAddress, attempt.Username, attempt.AttemptType)
	}

	fmt.Println("\nTotal Failed Attempts:", len(logEntries))
}
