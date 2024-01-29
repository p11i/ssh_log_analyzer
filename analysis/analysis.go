// analysis/analysis.go

package analysis

import "time"

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
