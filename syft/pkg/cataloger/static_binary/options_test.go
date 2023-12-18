package static_binary

import (
	"testing"

	"github.com/mitchellh/go-homedir"
	"github.com/stretchr/testify/assert"
)

func Test_Options(t *testing.T) {
	type opts struct {
		sharedLibDir  []string
		licenseDir    []string
		userTemplates []userMatchTemplates
		scanDepth     int
	}

	homedirCacheDisabled := homedir.DisableCache
	homedir.DisableCache = true
	t.Cleanup(func() {
		homedir.DisableCache = homedirCacheDisabled
	})

	allEnv := map[string]string{
		"HOME":      "/usr/home",
		"GOPATH":    "",
		"GOPROXY":   "",
		"GOPRIVATE": "",
		"GONOPROXY": "",
	}

	tests := []struct {
		name     string
		env      map[string]string
		opts     opts
		expected StaticBinaryCatalogerOpts
	}{
		{
			name: "set via env defaults",
			env: map[string]string{
				"GOPATH":    "/go",
				"GOPROXY":   "https://my.proxy",
				"GOPRIVATE": "my.private",
				"GONOPROXY": "no.proxy",
			},
			opts: opts{},
			expected: StaticBinaryCatalogerOpts{
				localSharedLibDir: []string(nil),
				localLicenseDir:   []string(nil),
				templates:         []userMatchTemplates{{pattern: "", namespace: "", version: ""}, {pattern: "", namespace: "", version: ""}},
				scanDepth:         1,
			},
		},
		{
			name: "set via configuration",
			env: map[string]string{
				"GOPATH":    "/go",
				"GOPROXY":   "https://my.proxy",
				"GOPRIVATE": "my.private",
				"GONOPROXY": "no.proxy",
			},
			opts: opts{
				sharedLibDir:  []string{"/opt/apps/oracle/oracle19/product/19.3.0/client_1/lib/"},
				licenseDir:    []string{"/opt/dev/int/domains/mf/mom-cpp/install/lib/"},
				userTemplates: []userMatchTemplates{},
				scanDepth:     2,
			},
			expected: StaticBinaryCatalogerOpts{
				localSharedLibDir: []string{"/opt/apps/oracle/oracle19/product/19.3.0/client_1/lib/"},
				localLicenseDir:   []string{"/opt/dev/int/domains/mf/mom-cpp/install/lib/"},
				templates:         []userMatchTemplates{{pattern: "", namespace: "", version: ""}, {pattern: "", namespace: "", version: ""}},
				scanDepth:         2,
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			for k, v := range allEnv {
				t.Setenv(k, v)
			}
			for k, v := range test.env {
				t.Setenv(k, v)
			}

			template := userMatchTemplates{
				pattern:   "",
				namespace: "",
				version:   "",
			}

			test.opts.userTemplates = append(test.opts.userTemplates, template)
			tempSlice := make([]string, 1)
			tempSlice = append(tempSlice, test.opts.userTemplates[0].pattern)
			tempSlice2 := make([]string, 1)
			tempSlice2 = append(tempSlice2, test.opts.userTemplates[0].namespace)
			tempSlice3 := make([]string, 1)
			tempSlice3 = append(tempSlice3, test.opts.userTemplates[0].version)

			got := NewStaticBinaryCatalogerOpts().
				WithLocalLibDir(test.opts.sharedLibDir).
				WithLocalLicenseDir(test.opts.licenseDir).
				WithUserTemplates(tempSlice, tempSlice2, tempSlice3).
				WithScanDepth(test.opts.scanDepth)

			assert.Equal(t, test.expected, got)
		})
	}
}
