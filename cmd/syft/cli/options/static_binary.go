package options

type staticBinary struct {
	LocalSharedLibDir     []string `json:"local-shared-lib-dir" yaml:"local-shared-lib-dir" mapstructure:"local-shared-lib-dir"`
	LocalLicenseDir       []string `json:"local-license-dir" yaml:"local-license-dir" mapstructure:"local-license-dir"`
	UserTemplateRegex     []string `json:"lib-regex-pattern" yaml:"lib-regex-pattern" mapstructure:"lib-regex-pattern"`
	UserTemplateNamespace []string `json:"lib-namespace" yaml:"lib-namespace" mapstructure:"lib-namespace"`
	UserTemplateVersion   []string `json:"lib-version" yaml:"lib-version" mapstructure:"lib-version"`
	ScanDepth             int      `json:"scan-depth" yaml:"scan-depth" mapstructure:"scan-depth"`
}
