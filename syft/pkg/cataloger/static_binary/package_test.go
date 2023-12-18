package static_binary

import (
	"testing"

	"github.com/anchore/syft/syft/pkg"
	"github.com/stretchr/testify/assert"
)

func Test_packageURL(t *testing.T) {

	tests := []struct {
		name     string
		pkg      pkg.StaticBinaryPackageMetadata
		expected string
	}{
		{
			name: "static-binary",
			pkg: pkg.StaticBinaryPackageMetadata{
				Name:    "github.com/anchore/syft",
				System:  "momentum",
				Version: "v0.1.0",
			},
			expected: "pkg:generic/momentum/github.com/anchore/syft@v0.1.0",
		},
		{
			name: "static binary short name",
			pkg: pkg.StaticBinaryPackageMetadata{
				Name:    "go.opencensus.io",
				System:  "momentum",
				Version: "v0.23.0",
			},
			expected: "pkg:generic/momentum/go.opencensus.io@v0.23.0",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			assert.Equal(t, test.expected, packageURL(test.pkg.Name, test.pkg.System, test.pkg.Version))
		})
	}
}
