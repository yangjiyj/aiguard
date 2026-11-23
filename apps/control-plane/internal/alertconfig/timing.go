package alertconfig

import (
	"os"
	"strconv"
	"strings"
	"time"
)

func seconds(name string, fallback, min, max int) time.Duration {
	n, err := strconv.Atoi(strings.TrimSpace(os.Getenv(name)))
	if err != nil || n < min || n > max {
		n = fallback
	}
	return time.Duration(n) * time.Second
}

// ReviewPendingTimeout is shared by queue eligibility and bridge disposition.
func ReviewPendingTimeout() time.Duration {
	return seconds("SECEVENT_REVIEW_PENDING_TIMEOUT_SECONDS", 900, 60, 86400)
}

// BridgeInterval bounds ordinary event visibility without a manual drain.
func BridgeInterval() time.Duration { return seconds("SECEVENT_BRIDGE_INTERVAL_SECONDS", 10, 1, 600) }
