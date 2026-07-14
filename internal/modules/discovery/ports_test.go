package discovery

import (
	"reflect"
	"testing"

	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"go.uber.org/zap/zaptest/observer"
)

// TestPortsForProfile_FullWithoutConfirmFallsBackAndWarns covers item 2's
// gap: PortProfile="full" requested without ConfirmFullPortScan must not
// silently fall back to "top1000" — it must log a single WARN-level
// message documenting the fallback (so the misconfiguration is visible
// in operational logs) and return exactly the top-1000 list, not the
// full 1-65535 range and not the quick list.
func TestPortsForProfile_FullWithoutConfirmFallsBackAndWarns(t *testing.T) {
	core, logs := observer.New(zap.WarnLevel)
	log := zap.New(core).Sugar()

	got := portsForProfile(PortProfileFull, false, log)

	want := top1000TCPPorts()
	if !reflect.DeepEqual(got, want) {
		t.Errorf("portsForProfile(full, confirmFull=false) returned %d ports, want the top1000 list (%d ports)", len(got), len(want))
	}
	if len(got) == len(fullPortRange()) {
		t.Errorf("portsForProfile(full, confirmFull=false) returned the full 65535-port range; it must fall back, not proceed")
	}
	if len(got) == len(DefaultPorts) {
		t.Errorf("portsForProfile(full, confirmFull=false) returned the quick list; it must fall back to top1000, not quick")
	}

	entries := logs.FilterLevelExact(zapcore.WarnLevel).All()
	if len(entries) != 1 {
		t.Fatalf("expected exactly one WARN log entry for the full->top1000 fallback, got %d", len(entries))
	}
	msg := entries[0].Message
	if msg == "" {
		t.Error("expected a non-empty WARN message documenting the fallback")
	}
}

// TestPortsForProfile_FullWithConfirmReturnsFullRangeNoWarn covers the
// opposite path: with ConfirmFullPortScan=true, "full" must return the
// entire 1-65535 range and must NOT log the fallback warning (there's no
// misconfiguration to warn about).
func TestPortsForProfile_FullWithConfirmReturnsFullRangeNoWarn(t *testing.T) {
	core, logs := observer.New(zap.WarnLevel)
	log := zap.New(core).Sugar()

	got := portsForProfile(PortProfileFull, true, log)

	want := fullPortRange()
	if !reflect.DeepEqual(got, want) {
		t.Errorf("portsForProfile(full, confirmFull=true) returned %d ports, want the full range (%d ports)", len(got), len(want))
	}
	if n := logs.FilterLevelExact(zapcore.WarnLevel).Len(); n != 0 {
		t.Errorf("expected no WARN log entries when ConfirmFullPortScan=true, got %d", n)
	}
}

// TestPortsForProfile_NilLoggerSafe confirms portsForProfile never
// dereferences a nil logger — callers in tests that don't care about the
// log line should be able to pass nil safely.
func TestPortsForProfile_NilLoggerSafe(t *testing.T) {
	got := portsForProfile(PortProfileFull, false, nil)
	want := top1000TCPPorts()
	if !reflect.DeepEqual(got, want) {
		t.Errorf("portsForProfile with nil logger returned %d ports, want top1000 (%d ports)", len(got), len(want))
	}
}

// TestPortsForProfile_OtherProfiles covers the non-"full" branches:
// "top1000" returns the embedded top-1000 list, anything else
// (including empty/unrecognized) returns the quick DefaultPorts list.
func TestPortsForProfile_OtherProfiles(t *testing.T) {
	if got := portsForProfile(PortProfileTop1000, false, nil); !reflect.DeepEqual(got, top1000TCPPorts()) {
		t.Errorf("portsForProfile(top1000) returned %d ports, want top1000 list (%d ports)", len(got), len(top1000TCPPorts()))
	}
	if got := portsForProfile("", false, nil); !reflect.DeepEqual(got, DefaultPorts) {
		t.Errorf("portsForProfile(\"\") returned %d ports, want DefaultPorts (%d ports)", len(got), len(DefaultPorts))
	}
	if got := portsForProfile("bogus-profile", false, nil); !reflect.DeepEqual(got, DefaultPorts) {
		t.Errorf("portsForProfile(bogus) returned %d ports, want DefaultPorts (%d ports)", len(got), len(DefaultPorts))
	}
}

// TestPortConcurrencyOrDefault covers the concurrency-default helper used
// by probePorts.
func TestPortConcurrencyOrDefault(t *testing.T) {
	if got := portConcurrencyOrDefault(0); got != defaultPortConcurrency {
		t.Errorf("portConcurrencyOrDefault(0) = %d, want default %d", got, defaultPortConcurrency)
	}
	if got := portConcurrencyOrDefault(-5); got != defaultPortConcurrency {
		t.Errorf("portConcurrencyOrDefault(-5) = %d, want default %d", got, defaultPortConcurrency)
	}
	if got := portConcurrencyOrDefault(50); got != 50 {
		t.Errorf("portConcurrencyOrDefault(50) = %d, want 50", got)
	}
}
