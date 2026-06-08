package artifact

import (
	"context"
	"errors"

	"golang.org/x/sync/errgroup"
	"golang.org/x/xerrors"
)

// FinalizeAnalysis waits for the in-flight analyzers and returns the most meaningful
// error between the synchronous walk and the async analyzers. When the walk
// failed it cancels the analyzers (via cancel) so they stop wasting work; the
// resulting context.Canceled from either side is then ignored in favour of the
// real cause. walkErr must already be wrapped by the caller.
func FinalizeAnalysis(eg *errgroup.Group, cancel context.CancelFunc, walkErr error) error {
	// If the walk failed synchronously, cancel the in-flight analyzers so they stop
	// wasting work (e.g. network calls) instead of running to completion.
	if walkErr != nil {
		cancel()
	}

	// Cancellation (from either an analyzer failure or the walk error above) makes the
	// other side return context.Canceled, masking the real cause (e.g. a remote 429).
	// Prefer the real error from either side over a context.Canceled.
	analyzeErr := eg.Wait()
	switch {
	case analyzeErr != nil && !errors.Is(analyzeErr, context.Canceled):
		return xerrors.Errorf("analyze error: %w", analyzeErr)
	case walkErr != nil:
		return walkErr
	case analyzeErr != nil:
		return xerrors.Errorf("analyze error: %w", analyzeErr)
	}
	return nil
}
