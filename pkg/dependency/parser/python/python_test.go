package python_test

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/aquasecurity/trivy/pkg/dependency/parser/python"
	"github.com/aquasecurity/trivy/pkg/digest"
	ftypes "github.com/aquasecurity/trivy/pkg/fanal/types"
)

func Test_NormalizePkgName(t *testing.T) {
	tests := []struct {
		pkgName   string
		lowerCase bool
		expected  string
	}{
		{
			pkgName:   "SecretStorage",
			lowerCase: true,
			expected:  "secretstorage",
		},
		{
			pkgName:   "SecretStorage",
			lowerCase: false,
			expected:  "SecretStorage",
		},
		{
			pkgName:   "pywin32-ctypes",
			lowerCase: true,
			expected:  "pywin32-ctypes",
		},
		{
			pkgName:   "jaraco.classes",
			lowerCase: true,
			expected:  "jaraco-classes",
		},
		{
			pkgName:   "green_gdk",
			lowerCase: true,
			expected:  "green-gdk",
		},
		{
			pkgName:   "foo--bar__baz",
			lowerCase: true,
			expected:  "foo-bar-baz",
		},
	}

	for _, tt := range tests {
		t.Run(tt.pkgName, func(t *testing.T) {
			assert.Equal(t, tt.expected, python.NormalizePkgName(tt.pkgName, tt.lowerCase))
		})
	}
}

func TestSetDistributions(t *testing.T) {
	sdist := ftypes.Distribution{
		Kind:     ftypes.DistributionKindSource,
		FileName: "foo-1.0.tar.gz",
		URL:      "https://files.example.com/foo-1.0.tar.gz",
		Digests: []digest.SourcedDigest{
			{
				Digest: "sha256:1111111111111111111111111111111111111111111111111111111111111111",
				Source: digest.SourceLockfile,
			},
		},
	}
	wheel := ftypes.Distribution{
		Kind:     ftypes.DistributionKindBuilt,
		FileName: "foo-1.0-py3-none-any.whl",
		URL:      "https://files.example.com/foo-1.0-py3-none-any.whl",
		Digests: []digest.SourcedDigest{
			{
				Digest: "sha256:2222222222222222222222222222222222222222222222222222222222222222",
				Source: digest.SourceLockfile,
			},
		},
	}

	tests := []struct {
		name  string
		dists []ftypes.Distribution
		want  ftypes.Package
	}{
		{
			name:  "one file",
			dists: []ftypes.Distribution{sdist},
			want: ftypes.Package{
				Name:          "foo",
				Digests:       sdist.Digests,
				Distributions: []ftypes.Distribution{sdist},
			},
		},
		{
			name:  "several files",
			dists: []ftypes.Distribution{sdist, wheel},
			want: ftypes.Package{
				Name:          "foo",
				Distributions: []ftypes.Distribution{sdist, wheel},
			},
		},
		{
			name: "no files",
			want: ftypes.Package{
				Name: "foo",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			pkg := ftypes.Package{Name: "foo"}
			python.SetDistributions(&pkg, tt.dists)
			assert.Equal(t, tt.want, pkg)
		})
	}
}

func TestRemoveCredentials(t *testing.T) {
	tests := []struct {
		name string
		url  string
		want string
	}{
		{
			name: "user and password",
			url:  "https://user:pass@pypi.example.com/simple",
			want: "https://pypi.example.com/simple",
		},
		{
			name: "token only",
			url:  "https://token@pypi.example.com/simple",
			want: "https://pypi.example.com/simple",
		},
		{
			name: "unexpanded variables",
			url:  "https://${REPO_USER}:${REPO_PASS}@pypi.example.com/simple",
			want: "https://pypi.example.com/simple",
		},
		{
			name: "at sign in path",
			url:  "https://pypi.example.com/simple/@scope/foo",
			want: "https://pypi.example.com/simple/@scope/foo",
		},
		{
			name: "without credentials",
			url:  "https://pypi.example.com/simple",
			want: "https://pypi.example.com/simple",
		},
		{
			name: "relative path",
			url:  "../dist/foo-1.0.tar.gz",
			want: "../dist/foo-1.0.tar.gz",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, python.RemoveCredentials(tt.url))
		})
	}
}

func TestFileNameFromURL(t *testing.T) {
	tests := []struct {
		name string
		url  string
		want string
	}{
		{
			name: "index file",
			url:  "https://files.pythonhosted.org/packages/f6/40/318e58f6/anyio-4.7.0.tar.gz",
			want: "anyio-4.7.0.tar.gz",
		},
		{
			name: "percent-encoded",
			url:  "https://download.example.com/whl/cpu/torch-2.5.1%2Bcpu-cp312-cp312-linux_x86_64.whl",
			want: "torch-2.5.1+cpu-cp312-cp312-linux_x86_64.whl",
		},
		{
			name: "query and fragment",
			url:  "https://files.example.com/foo-1.0.tar.gz?token=abc#sha256=123",
			want: "foo-1.0.tar.gz",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, python.FileNameFromURL(tt.url))
		})
	}
}
