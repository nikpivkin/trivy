package rego_test

import (
	"context"
	"testing"

	"github.com/aquasecurity/trivy/pkg/iac/rego"
	"github.com/aquasecurity/trivy/pkg/iac/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestUnifiedScanner_ScanInput(t *testing.T) {
	srcFS := CreateFS(t, map[string]string{
		"policies/test.rego": `
package defsec.test

deny {
    input.evil
}
`,
	})

	scanner := rego.NewUnifiedScanner(
		rego.WithPolicyDirs("policies"),
	)
	require.NoError(t, scanner.LoadPolicies(srcFS))

	results, err := scanner.ScanInput(context.TODO(), types.SourceJSON, rego.Input{
		Path: "/evil.lol",
		Contents: map[string]any{
			"evil": true,
		},
	})
	require.NoError(t, err)

	assert.Len(t, results, 1)
	assert.Len(t, results.GetFailed(), 1)
}
