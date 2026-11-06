package python

import (
	"net/url"
	"path"
	"regexp"
	"strings"

	ftypes "github.com/aquasecurity/trivy/pkg/fanal/types"
)

var normalizePkgNameRegexp = regexp.MustCompile(`[-_.]+`)

// NormalizePkgName normalizes the package name based on pep-0503 (with the option to disable conversion to lowercase).
// cf. https://peps.python.org/pep-0503/#normalized-names:
// The name should be lowercased with all runs of the characters ., -, or _ replaced with a single - character.
func NormalizePkgName(name string, inLowerCase bool) string {
	name = normalizePkgNameRegexp.ReplaceAllString(name, "-")

	// pep-0503 requires that all packages names MUST be lowercase.
	// But there are cases where the original case should be preserved (e.g. dist-info dir names).
	if inLowerCase {
		name = strings.ToLower(name)
	}
	return name
}

// SetDistributions stores the distribution files recorded in a lock file for the package.
// The lock file must record all files of the package version. When it records one file, the
// package can be installed only from that file, so its digests become digests of the package.
func SetDistributions(pkg *ftypes.Package, dists []ftypes.Distribution) {
	pkg.Distributions = dists
	if len(dists) == 1 {
		pkg.AddDigests(dists[0].Digests...)
	}
}

// RemoveCredentials removes the userinfo from a URL. The userinfo is cut without parsing the
// URL, because lock files may keep unexpanded variables such as ${PASS} there, which
// url.Parse rejects.
func RemoveCredentials(rawURL string) string {
	scheme, rest, ok := strings.Cut(rawURL, "://")
	if !ok {
		return rawURL
	}
	authority := rest
	if i := strings.IndexAny(rest, "/?#"); i >= 0 {
		authority = rest[:i]
	}
	i := strings.LastIndex(authority, "@")
	if i < 0 {
		return rawURL
	}
	return scheme + "://" + rest[i+1:]
}

// FileNameFromURL returns the last path segment of a URL, percent-decoded.
func FileNameFromURL(rawURL string) string {
	if i := strings.IndexAny(rawURL, "?#"); i >= 0 {
		rawURL = rawURL[:i]
	}
	name := path.Base(rawURL)
	if unescaped, err := url.PathUnescape(name); err == nil {
		name = unescaped
	}
	return name
}
