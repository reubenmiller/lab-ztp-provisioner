package clock_test

import (
	"errors"
	"io"
	"log/slog"
	"sync"
	"testing"
	"time"

	"github.com/thin-edge/tedge-zerotouch-provisioning/internal/agent/clock"
)

func TestParsePolicy(t *testing.T) {
	cases := []struct {
		in   string
		want clock.Policy
		err  bool
	}{
		{"", clock.PolicyAuto, false},
		{"auto", clock.PolicyAuto, false},
		{"AUTO", clock.PolicyAuto, false},
		{" auto ", clock.PolicyAuto, false},
		{"off", clock.PolicyOff, false},
		{"disabled", clock.PolicyOff, false},
		{"false", clock.PolicyOff, false},
		{"always", clock.PolicyAlways, false},
		{"force", clock.PolicyAlways, false},
		{"sometimes", clock.PolicyAuto, true},
	}
	for _, c := range cases {
		got, err := clock.ParsePolicy(c.in)
		if (err != nil) != c.err {
			t.Errorf("ParsePolicy(%q): err=%v want err=%v", c.in, err, c.err)
		}
		if got != c.want && !c.err {
			t.Errorf("ParsePolicy(%q) = %v, want %v", c.in, got, c.want)
		}
	}
}

func TestPolicyString(t *testing.T) {
	if clock.PolicyAuto.String() != "auto" {
		t.Errorf("PolicyAuto.String() = %q", clock.PolicyAuto.String())
	}
	if clock.PolicyOff.String() != "off" {
		t.Errorf("PolicyOff.String() = %q", clock.PolicyOff.String())
	}
	if clock.PolicyAlways.String() != "always" {
		t.Errorf("PolicyAlways.String() = %q", clock.PolicyAlways.String())
	}
}

// TestDecide exercises the policy state machine without touching the host
// clock. Each row encodes a (policy, delta) pair and the expected Action.
func TestDecide(t *testing.T) {
	now := time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC)
	threshold := 60 * time.Second

	cases := []struct {
		name   string
		policy clock.Policy
		target time.Time
		want   string
	}{
		{"zero target", clock.PolicyAuto, time.Time{}, "skip-zero"},
		{"off skips", clock.PolicyOff, now.Add(time.Hour), "skip-policy"},
		{"auto small forward drift", clock.PolicyAuto, now.Add(30 * time.Second), "skip-threshold"},
		{"auto small backward drift", clock.PolicyAuto, now.Add(-30 * time.Second), "skip-threshold"},
		{"auto refuses backward", clock.PolicyAuto, now.Add(-2 * time.Hour), "skip-backward"},
		{"auto advances forward", clock.PolicyAuto, now.Add(5 * time.Minute), "advance"},
		{"always small drift skipped", clock.PolicyAlways, now.Add(10 * time.Second), "skip-threshold"},
		{"always sets forward", clock.PolicyAlways, now.Add(5 * time.Minute), "set"},
		{"always sets backward", clock.PolicyAlways, now.Add(-5 * time.Minute), "set"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := clock.Decide(now, c.target, c.policy, threshold)
			if got.Action != c.want {
				t.Errorf("Action = %q, want %q (reason=%q)", got.Action, c.want, got.Reason)
			}
		})
	}
}

func TestDecide_DefaultThreshold(t *testing.T) {
	now := time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC)
	// 30s forward with threshold=0 should fall back to DefaultThreshold (60s)
	// and therefore skip.
	d := clock.Decide(now, now.Add(30*time.Second), clock.PolicyAuto, 0)
	if d.Action != "skip-threshold" {
		t.Errorf("expected skip-threshold under default threshold, got %q", d.Action)
	}
	if d.Threshold != clock.DefaultThreshold {
		t.Errorf("expected threshold %v, got %v", clock.DefaultThreshold, d.Threshold)
	}
}

// fakeSetter records calls and optionally returns an error.
type fakeSetter struct {
	mu     sync.Mutex
	called []time.Time
	err    error
}

func (f *fakeSetter) set(t time.Time) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.called = append(f.called, t)
	return f.err
}

// withFakeSetter swaps clock.SetClockFunc for the duration of fn.
func withFakeSetter(f *fakeSetter, fn func()) {
	prev := clock.SetClockFunc
	clock.SetClockFunc = f.set
	defer func() { clock.SetClockFunc = prev }()
	fn()
}

func discardLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

func TestAdjust_SkipsForOffPolicy(t *testing.T) {
	f := &fakeSetter{}
	withFakeSetter(f, func() {
		err := clock.Adjust(time.Now().Add(time.Hour), clock.PolicyOff, 0, discardLogger())
		if err != nil {
			t.Fatalf("Adjust returned err: %v", err)
		}
	})
	if len(f.called) != 0 {
		t.Errorf("PolicyOff must not call setter, got %d calls", len(f.called))
	}
}

func TestAdjust_SkipsZeroTarget(t *testing.T) {
	f := &fakeSetter{}
	withFakeSetter(f, func() {
		_ = clock.Adjust(time.Time{}, clock.PolicyAlways, 0, discardLogger())
	})
	if len(f.called) != 0 {
		t.Errorf("zero target must never trigger a set, got %d calls", len(f.called))
	}
}

func TestAdjust_AdvancesWhenFarBehind(t *testing.T) {
	f := &fakeSetter{}
	target := time.Now().Add(2 * time.Hour) // well past the 60 s threshold
	withFakeSetter(f, func() {
		if err := clock.Adjust(target, clock.PolicyAuto, 0, discardLogger()); err != nil {
			t.Fatalf("Adjust err: %v", err)
		}
	})
	if len(f.called) != 1 {
		t.Fatalf("expected one set call, got %d", len(f.called))
	}
	if !f.called[0].Equal(target) {
		t.Errorf("setter was called with %v, want %v", f.called[0], target)
	}
}

func TestAdjust_AutoRefusesBackward(t *testing.T) {
	f := &fakeSetter{}
	target := time.Now().Add(-2 * time.Hour)
	withFakeSetter(f, func() {
		_ = clock.Adjust(target, clock.PolicyAuto, 0, discardLogger())
	})
	if len(f.called) != 0 {
		t.Errorf("auto policy must not move clock backwards, got %d calls", len(f.called))
	}
}

func TestAdjust_AlwaysAllowsBackward(t *testing.T) {
	f := &fakeSetter{}
	target := time.Now().Add(-2 * time.Hour)
	withFakeSetter(f, func() {
		if err := clock.Adjust(target, clock.PolicyAlways, 0, discardLogger()); err != nil {
			t.Fatalf("Adjust err: %v", err)
		}
	})
	if len(f.called) != 1 {
		t.Errorf("always policy must move clock backward, got %d calls", len(f.called))
	}
}

func TestAdjust_PropagatesSetterError(t *testing.T) {
	wantErr := errors.New("EPERM: simulated")
	f := &fakeSetter{err: wantErr}
	target := time.Now().Add(2 * time.Hour)
	var got error
	withFakeSetter(f, func() {
		got = clock.Adjust(target, clock.PolicyAuto, 0, discardLogger())
	})
	if got == nil || !errors.Is(got, wantErr) {
		t.Errorf("Adjust err = %v, want chain containing %v", got, wantErr)
	}
}
