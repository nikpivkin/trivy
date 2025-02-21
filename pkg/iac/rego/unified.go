package rego

import (
	"context"
	"io/fs"

	"github.com/aquasecurity/trivy/pkg/iac/scan"
	"github.com/aquasecurity/trivy/pkg/iac/scanners/options"
	"github.com/aquasecurity/trivy/pkg/iac/types"
)

// UnifiedScanner is a wrapper over Scanner that does not require specifying
// the source type at creation to determine the default schema for type checking
// when compiling Rego. This scanner also filters checks based on the source type,
// just like the Rego scanner, but the source is passed directly when scanning the input.
// This allows a single scanner instance to be used across different IaC scanners.
type UnifiedScanner struct {
	underlying *Scanner
}

func NewUnifiedScanner(opts ...options.ScannerOption) *UnifiedScanner {
	return &UnifiedScanner{
		underlying: NewScanner("", opts...),
	}
}

func (s *UnifiedScanner) LoadPolicies(fsys fs.FS) error {
	return s.underlying.LoadPolicies(fsys)
}

func (s *UnifiedScanner) ScanInput(ctx context.Context, sourceType types.Source, inputs ...Input) (scan.Results, error) {
	return s.underlying.scanInput(ctx, sourceType, inputs...)
}
