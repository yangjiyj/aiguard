package handler

import (
	"net/http"
	"time"
)

func defaultBoundedTimeWindow(r *http.Request, duration time.Duration) (time.Time, time.Time, error) {
	now := time.Now().UTC()
	start := now.Add(-duration)
	end := now
	if parsed, err := parseFlexibleTime(firstQuery(r, "start_time", "start", "start_date", "from")); err != nil {
		return time.Time{}, time.Time{}, err
	} else if !parsed.IsZero() {
		start = parsed
	}
	if parsed, err := parseFlexibleTime(firstQuery(r, "end_time", "end", "end_date", "to")); err != nil {
		return time.Time{}, time.Time{}, err
	} else if !parsed.IsZero() {
		end = parsed
	}
	return start, end, nil
}
