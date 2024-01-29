// parsing/parsing.go

package parsing

import "time"

type LogEntry struct {
	Time        time.Time
	IPAddress   string
	Username    string
	AttemptType string
}
