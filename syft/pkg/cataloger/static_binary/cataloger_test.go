package static_binary

import (
	"testing"

	"github.com/anchore/syft/syft/pkg/cataloger/internal/pkgtest"
)

func Test_Static_Binary_Cataloger_Globs(t *testing.T) {
	tests := []struct {
		name     string
		fixture  string
		expected []string
	}{
		{
			name:    "obtain static-binary files",
			fixture: "test-fixtures/glob-paths",
			expected: []string{
				"partial-binary",
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			pkgtest.NewCatalogTester().
				FromDirectory(t, test.fixture).
				ExpectsResolverContentQueries(test.expected).
				TestCataloger(t, NewStaticBinaryPackageCataloger(StaticBinaryCatalogerOpts{}))
		})
	}
}

func Test_Default_Cataloger_Config(t *testing.T) {

	// g := StaticBinaryCatalogerOpts{}

	// g.localSharedLibDir = nil
	// g.scanDepth = 1
	// return g
}
