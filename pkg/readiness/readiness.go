// Package readiness waits until this shell can use a PIM group or Entra role
// that was just activated, by asking the services it grants access to whether
// they accept this shell's own Azure CLI credentials.
//
// The activation itself takes effect within seconds, but the access tokens az
// already has cached were issued before it and are not updated, so az, and
// kubectl signing in through az, keep being refused until those tokens expire.
// The wait therefore drops az's cached access tokens (az mints new ones from its
// refresh token on the next call) and repeats a round of read-only checks until
// every check passes.
//
// It serves PIM for Groups and PIM for Entra roles. Azure resource roles
// (activate resource) are not wired up.
package readiness

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"sync"
	"time"
)

// Outcome of one check in one round.
type Outcome int

const (
	// Fail means the service refused this shell's credentials, so the access
	// the group grants is not usable from here yet.
	Fail Outcome = iota
	// Pass means the service accepted this shell's credentials.
	Pass
	// Unknown means the answer said nothing about the credentials: a firewall,
	// a network error, or a status the check does not recognise.
	Unknown
)

// Result is what one check found in one round.
type Result struct {
	Outcome Outcome
	Detail  string
}

// Check asks one service whether this shell's credentials can use something
// the group grants, without changing anything.
type Check interface {
	Name() string
	Run(ctx context.Context, tokens TokenSource) Result
}

// TokenSource returns an access token for scope from this shell's Azure CLI.
type TokenSource func(ctx context.Context, scope string) (string, error)

// ErrNotReady is returned when the checks have not all passed within the
// timeout.
var ErrNotReady = errors.New("this shell's credentials did not pass every check in time")

// Waiter runs every check once per round until all of them pass.
type Waiter struct {
	Checks []Check
	Tokens TokenSource
	// Refresh makes the next round use newly minted tokens. It runs before the
	// first round and again after any round in which a check failed.
	Refresh  func() error
	Interval time.Duration
	Timeout  time.Duration

	// Overridable in tests.
	now   func() time.Time
	sleep func(context.Context, time.Duration) error
}

// Unverified is a check that never produced an answer about the credentials.
type Unverified struct {
	Name   string
	Detail string
}

// Report describes how a wait ended.
type Report struct {
	Elapsed    time.Duration
	Unverified []Unverified
	// Pending names the checks that had not passed when the wait gave up.
	Pending []string
}

// readyRounds is how many rounds in a row must pass. Requests that land on
// different frontends of a service can disagree while a change spreads, so
// one passing round is not taken as final.
const readyRounds = 2

// checkTimeout bounds a single check, so one hung request cannot stall a round.
const checkTimeout = 30 * time.Second

// Wait returns once every check has passed readyRounds rounds in a row. A
// check that has only ever answered Unknown does not hold the wait up; it is
// reported as unverified instead. A check that has answered, and then turns
// Unknown, does hold it up. With no checks at all it refreshes once and
// returns, since new tokens are all it can offer then.
func (w *Waiter) Wait(ctx context.Context) (Report, error) {
	now, sleep := w.now, w.sleep
	if now == nil {
		now = time.Now
	}
	if sleep == nil {
		sleep = sleepContext
	}

	start := now()
	if len(w.Checks) == 0 {
		if err := w.Refresh(); err != nil {
			return Report{}, fmt.Errorf("refreshing this shell's Azure CLI tokens: %w", err)
		}
		return Report{Elapsed: now().Sub(start)}, nil
	}
	answered := make([]bool, len(w.Checks))
	var last []Result
	passedInRow := 0
	refresh := true
	for {
		if refresh {
			if err := w.Refresh(); err != nil {
				return Report{Elapsed: now().Sub(start)}, fmt.Errorf("refreshing this shell's Azure CLI tokens: %w", err)
			}
		}

		last = w.runRound(ctx)
		var pending []string
		refresh = false
		for i, result := range last {
			switch result.Outcome {
			case Pass:
				answered[i] = true
			case Fail:
				answered[i] = true
				refresh = true
				pending = append(pending, w.Checks[i].Name())
			case Unknown:
				if answered[i] {
					pending = append(pending, w.Checks[i].Name())
				}
			}
		}

		elapsed := now().Sub(start)
		if len(pending) == 0 {
			passedInRow++
		} else {
			passedInRow = 0
		}
		if passedInRow >= readyRounds {
			report := Report{Elapsed: elapsed}
			for i, result := range last {
				if !answered[i] {
					report.Unverified = append(report.Unverified, Unverified{Name: w.Checks[i].Name(), Detail: result.Detail})
				}
			}
			return report, nil
		}
		// A round that passed earns its confirming round even past the timeout.
		if elapsed >= w.Timeout && len(pending) > 0 {
			return Report{Elapsed: elapsed, Pending: pending}, ErrNotReady
		}

		if len(pending) == 0 {
			slog.Info("Every check passes; confirming", "elapsed", elapsed.Round(time.Second).String())
		} else {
			slog.Info("Waiting until this shell's credentials pass every check", "pending", len(pending), "elapsed", elapsed.Round(time.Second).String())
			for _, name := range pending {
				slog.Debug("Not passing yet", "check", name)
			}
		}
		if err := sleep(ctx, w.Interval); err != nil {
			return Report{Elapsed: now().Sub(start), Pending: pending}, err
		}
	}
}

// runRound runs every check concurrently. Checks that need the same token
// share one fetch, because each fetch starts az.
func (w *Waiter) runRound(ctx context.Context) []Result {
	tokens := sharedPerRound(w.Tokens)
	results := make([]Result, len(w.Checks))
	var wg sync.WaitGroup
	for i, check := range w.Checks {
		wg.Go(func() {
			checkCtx, cancel := context.WithTimeout(ctx, checkTimeout)
			defer cancel()
			results[i] = check.Run(checkCtx, tokens)
		})
	}
	wg.Wait()
	return results
}

func sharedPerRound(tokens TokenSource) TokenSource {
	var mu sync.Mutex
	fetches := map[string]func() (string, error){}
	return func(ctx context.Context, scope string) (string, error) {
		mu.Lock()
		fetch, ok := fetches[scope]
		if !ok {
			fetch = sync.OnceValues(func() (string, error) { return tokens(ctx, scope) })
			fetches[scope] = fetch
		}
		mu.Unlock()
		return fetch()
	}
}

func sleepContext(ctx context.Context, d time.Duration) error {
	timer := time.NewTimer(d)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}
