package static_binary

type StaticBinaryCatalogerOpts struct {
	localSharedLibDir []string
	localLicenseDir   []string
	templates         []userMatchTemplates
	scanDepth         int
}

type userMatchTemplates struct {
	pattern   string
	namespace string
	version   string
}

func NewStaticBinaryCatalogerOpts() StaticBinaryCatalogerOpts {
	g := StaticBinaryCatalogerOpts{}

	g.localSharedLibDir = nil
	g.scanDepth = 1
	return g
}

func (g StaticBinaryCatalogerOpts) WithLocalLibDir(input []string) StaticBinaryCatalogerOpts {
	if input == nil {
		return g
	}

	g.localSharedLibDir = input

	return g

}
func (g StaticBinaryCatalogerOpts) WithScanDepth(input int) StaticBinaryCatalogerOpts {
	if input == 0 {
		return g
	}
	g.scanDepth = input
	return g
}

func (g StaticBinaryCatalogerOpts) WithLocalLicenseDir(input []string) StaticBinaryCatalogerOpts {
	if input == nil {
		return g
	}

	g.localLicenseDir = input

	return g

}

func (g StaticBinaryCatalogerOpts) WithUserTemplates(patterns []string, namespaces []string, versions []string) StaticBinaryCatalogerOpts {
	if patterns == nil {
		return g
	}
	templates := []userMatchTemplates{}
	for i, pattern := range patterns {

		template := userMatchTemplates{
			pattern:   pattern,
			namespace: namespaces[i],
			version:   versions[i],
		}
		templates = append(templates, template)

	}

	g.templates = templates

	return g

}
