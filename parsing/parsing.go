// parsing/parsing.go

package parsing

import (
	"bufio"
	"os"
	"regexp"
	"strings"
	"time"
)

type LogEntry struct {
	Time        time.Time
	IPAddress   string
	Username    string
	AttemptType string
}

func ParseSSHLogs(logFile string) ([]LogEntry, error) {
	var logEntries []LogEntry
	regexPattern := regexp.MustCompile(`(?i)(\S+ \d+ \d+:\d+:\d+) Failed (password|publickey) for (invalid user |)(\S+) from (\S+)`)

	file, err := os.Open(logFile)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := scanner.Text()
		matches := regexPattern.FindStringSubmatch(line)

		if len(matches) > 0 {
			timeStr := matches[1]
			time, err := time.Parse("Jan 2 15:04:05", timeStr)
			if err != nil {
				// Handle parsing error
				continue
			}

			attemptType := strings.ToLower(matches[2])
			username := matches[4]
			ipAddress := matches[len(matches)-1]

			logEntry := LogEntry{
				Time:        time,
				IPAddress:   ipAddress,
				Username:    username,
				AttemptType: attemptType,
			}
			logEntries = append(logEntries, logEntry)
		}
	}

	if err := scanner.Err(); err != nil {
		return nil, err
	}

	return logEntries, nil
}
