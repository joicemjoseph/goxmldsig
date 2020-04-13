package dsig

import (
	"time"

	"github.com/jonboulle/clockwork"
)

// Clock wraps a clockwork.Clock (which could be real or fake) in order
// to default to a real clock when a nil *Clock is used. In other words,
// if you attempt to use a nil *Clock it will defer to the real system
// clock. This allows Clock to be easily added to structs with methods
// that currently reference the time package, without requiring every
// instantiation of that struct to be updated.
type Clock struct {
	wrapped clockwork.Clock
}

func (c *Clock) getWrapped() clockwork.Clock {
	if c == nil {
		return clockwork.NewRealClock()
	}

	return c.wrapped
}

// After method to chain execution chain.
func (c *Clock) After(d time.Duration) <-chan time.Time {
	return c.getWrapped().After(d)
}

// Sleep for duration 'd'.
func (c *Clock) Sleep(d time.Duration) {
	c.getWrapped().Sleep(d)
}

// Now returns momentary time object.
func (c *Clock) Now() time.Time {
	return c.getWrapped().Now()
}

// NewRealClock will create new clock object.s
func NewRealClock() *Clock {
	return &Clock{
		wrapped: clockwork.NewRealClock(),
	}
}

// NewFakeClock for testing purpose.
func NewFakeClock(wrapped clockwork.Clock) *Clock {
	return &Clock{
		wrapped: wrapped,
	}
}

// NewFakeClockAt for testing for picking a particular time point.
func NewFakeClockAt(t time.Time) *Clock {
	return &Clock{
		wrapped: clockwork.NewFakeClockAt(t),
	}
}
