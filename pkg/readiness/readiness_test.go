package readiness

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// scriptedCheck answers with the next outcome of its script each round and
// keeps repeating the last one.
type scriptedCheck struct {
	name     string
	outcomes []Outcome
	calls    int
}

func (c *scriptedCheck) Name() string { return c.name }

func (c *scriptedCheck) Run(context.Context, TokenSource) Result {
	outcome := c.outcomes[min(c.calls, len(c.outcomes)-1)]
	c.calls++
	return Result{Outcome: outcome, Detail: c.name + " detail"}
}

// newTestWaiter returns a waiter on a fake clock that each sleep advances,
// and a pointer to how many times it refreshed.
func newTestWaiter(checks ...Check) (waiter *Waiter, refreshes *int) {
	clock := time.Unix(0, 0)
	refreshes = new(int)
	waiter = &Waiter{
		Checks:   checks,
		Tokens:   func(context.Context, string) (string, error) { return "token", nil },
		Refresh:  func() error { *refreshes++; return nil },
		Interval: 5 * time.Second,
		Timeout:  30 * time.Second,
		now:      func() time.Time { return clock },
		sleep: func(_ context.Context, d time.Duration) error {
			clock = clock.Add(d)
			return nil
		},
	}
	return waiter, refreshes
}

func TestWaitReturnsAfterTwoPassingRounds(t *testing.T) {
	check := &scriptedCheck{name: "a", outcomes: []Outcome{Pass}}
	waiter, refreshes := newTestWaiter(check)

	report, err := waiter.Wait(context.Background())

	require.NoError(t, err)
	assert.Equal(t, 2, check.calls)
	assert.Equal(t, 1, *refreshes, "only the first round refreshes when nothing fails")
	assert.Equal(t, 5*time.Second, report.Elapsed)
	assert.Empty(t, report.Unverified)
}

func TestWaitRefreshesAfterEveryFailingRound(t *testing.T) {
	check := &scriptedCheck{name: "a", outcomes: []Outcome{Fail, Fail, Pass}}
	waiter, refreshes := newTestWaiter(check)

	report, err := waiter.Wait(context.Background())

	require.NoError(t, err)
	assert.Equal(t, 4, check.calls)
	assert.Equal(t, 3, *refreshes, "before the first round and after each of the two failing ones")
	assert.Equal(t, 15*time.Second, report.Elapsed)
}

func TestWaitGivesUpAtTheTimeout(t *testing.T) {
	passing := &scriptedCheck{name: "passing", outcomes: []Outcome{Pass}}
	failing := &scriptedCheck{name: "failing", outcomes: []Outcome{Fail}}
	waiter, _ := newTestWaiter(passing, failing)

	report, err := waiter.Wait(context.Background())

	require.ErrorIs(t, err, ErrNotReady)
	assert.Equal(t, []string{"failing"}, report.Pending)
	assert.Equal(t, 30*time.Second, report.Elapsed)
}

func TestWaitReportsChecksThatNeverAnswered(t *testing.T) {
	passing := &scriptedCheck{name: "passing", outcomes: []Outcome{Pass}}
	firewalled := &scriptedCheck{name: "firewalled", outcomes: []Outcome{Unknown}}
	waiter, _ := newTestWaiter(passing, firewalled)

	report, err := waiter.Wait(context.Background())

	require.NoError(t, err)
	assert.Equal(t, []Unverified{{Name: "firewalled", Detail: "firewalled detail"}}, report.Unverified)
}

func TestWaitHoldsForACheckThatAnsweredAndThenWentQuiet(t *testing.T) {
	flaky := &scriptedCheck{name: "flaky", outcomes: []Outcome{Pass, Unknown, Unknown, Pass}}
	waiter, refreshes := newTestWaiter(flaky)

	report, err := waiter.Wait(context.Background())

	require.NoError(t, err)
	assert.Equal(t, 5, flaky.calls)
	assert.Equal(t, 1, *refreshes, "an unknown answer is no reason to mint new tokens")
	assert.Empty(t, report.Unverified)
}

func TestWaitWithNothingToCheckRefreshesOnce(t *testing.T) {
	waiter, refreshes := newTestWaiter()

	report, err := waiter.Wait(context.Background())

	require.NoError(t, err)
	assert.Equal(t, 1, *refreshes)
	assert.Zero(t, report.Elapsed, "nothing to check means nothing to wait for")
}

func TestWaitStopsWhenTheRefreshFails(t *testing.T) {
	check := &scriptedCheck{name: "a", outcomes: []Outcome{Pass}}
	waiter, _ := newTestWaiter(check)
	refreshErr := errors.New("cache is encrypted")
	waiter.Refresh = func() error { return refreshErr }

	_, err := waiter.Wait(context.Background())

	require.ErrorIs(t, err, refreshErr)
	assert.Zero(t, check.calls)
}

func TestWaitStopsWhenTheContextEnds(t *testing.T) {
	check := &scriptedCheck{name: "a", outcomes: []Outcome{Fail}}
	waiter, _ := newTestWaiter(check)
	waiter.sleep = func(context.Context, time.Duration) error { return context.Canceled }

	_, err := waiter.Wait(context.Background())

	require.ErrorIs(t, err, context.Canceled)
}

func TestSharedPerRoundFetchesEachScopeOnce(t *testing.T) {
	var fetches atomic.Int32
	tokens := sharedPerRound(func(_ context.Context, scope string) (string, error) {
		fetches.Add(1)
		time.Sleep(10 * time.Millisecond)
		return "token for " + scope, nil
	})

	var wg sync.WaitGroup
	for range 10 {
		wg.Go(func() {
			token, err := tokens(context.Background(), armScope)
			assert.NoError(t, err)
			assert.Equal(t, "token for "+armScope, token)
		})
	}
	wg.Wait()
	_, err := tokens(context.Background(), storageScope)
	require.NoError(t, err)

	assert.Equal(t, int32(2), fetches.Load())
}
