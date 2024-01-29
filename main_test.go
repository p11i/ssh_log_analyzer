package main

import (
	parsing "p11i/ssh_log_analyzer/parsing"
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
