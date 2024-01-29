package main

import (
	analysis "p11i/ssh_log_analyzer/analysis"
	parsing "p11i/ssh_log_analyzer/parsing"
	"testing"
	"time"
)

// Mock log entries for testing
var mockLogEntries = []parsing.LogEntry{
	{Time: time.Now().Add(-2 * time.Hour), IPAddress: "192.168.1.1", Username: "user1", AttemptType: "password"},
	{Time: time.Now().Add(-1 * time.Hour), IPAddress: "192.168.1.2", Username: "user2", AttemptType: "password"},
	{Time: time.Now().Add(-1 * time.Hour), IPAddress: "192.168.1.3", Username: "user3", AttemptType: "password"},
	{Time: time.Now().Add(-1 * time.Hour), IPAddress: "192.168.1.4", Username: "user4", AttemptType: "password"},
	{Time: time.Now(), IPAddress: "192.168.1.5", Username: "user1", AttemptType: "publickey"},
}

func TestFilterResults(t *testing.T) {
	// Test filtering by username
	filteredUser := analysis.FilterResults(mockLogEntries, "user1", "", time.Now().Add(-3*time.Hour))
	if len(filteredUser) != 2 {
		t.Errorf("Expected 2 entries for user1, got %d", len(filteredUser))
	}

	// Test filtering by non-existent username
	filteredNonExistentUser := analysis.FilterResults(mockLogEntries, "nonexistentuser", "", time.Now().Add(-3*time.Hour))
	if len(filteredNonExistentUser) != 0 {
		t.Errorf("Expected 0 entries for nonexistentuser, got %d", len(filteredNonExistentUser))
	}
}
