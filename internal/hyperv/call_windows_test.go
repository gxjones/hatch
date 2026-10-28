package hyperv

import (
	"strings"
	"testing"
	"time"
)

func TestCallStopsAtDeadline(t *testing.T) {
	prev := callTimeouts["doctor"]
	callTimeouts["doctor"] = 50 * time.Millisecond
	defer func() { callTimeouts["doctor"] = prev }()

	start := time.Now()
	_, err := DoctorReport()
	if err == nil || !strings.Contains(err.Error(), "did not finish") {
		t.Fatalf("err %v", err)
	}
	if took := time.Since(start); took > 10*time.Second {
		t.Fatalf("took %s", took)
	}
}
