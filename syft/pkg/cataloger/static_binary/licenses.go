package static_binary

import (
	//"fmt"
	"os"
	"path"
	"strings"

	"github.com/anchore/syft/internal/licenses"
	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/pkg"
)

type staticLicenses struct {
	opts StaticBinaryCatalogerOpts
}

func newStaticLicenses(opts StaticBinaryCatalogerOpts) staticLicenses {
	return staticLicenses{
		opts: opts,
	}
}

func (c *staticLicenses) getLicenses(resolver file.Resolver, filename string, location file.Location) (licenses []pkg.License, err error) {

	currentDir, _ := path.Split(string(location.Reference().RealPath))
	if c.opts.localLicenseDir != nil {
		getLicenseFromOptionsPath(c, resolver, filename, currentDir, c.opts.localLicenseDir)

	} else {
		//locations, _ = resolver.FilesByGlob(string(location.Reference().RealPath))

		licenses, err = getLicensesFromLocal(c, resolver, filename, currentDir)
		if err != nil || len(licenses) > 0 {
			return requireCollection(licenses), err
		}
	}

	return requireCollection(licenses), err
}

func getLicenseFromOptionsPath(c *staticLicenses, resolver file.Resolver, globMatch string, currentDir string, pathsToCheck []string) (out []pkg.License, err error) {
	var licenses []pkg.License
	for _, loc := range c.opts.localLicenseDir {
		licenses, err = findLicenses(c, resolver, globMatch, loc)
		if licenses != nil {
			//fmt.Printf("We found it in getLicenseFromOptionsPath! %v\n", globMatch)
			return licenses, err
		}

	}
	//user suppled path did not have what we need, check current dir of the scan just in case.
	if licenses == nil {
		licenses, err = getLicensesFromLocal(c, resolver, globMatch, currentDir)
	}
	return licenses, err
}

func getLicensesFromLocal(c *staticLicenses, resolver file.Resolver, globMatch string, pathToCheck string) (out []pkg.License, err error) {

	//fmt.Printf("We found it in getLicensesFromLocal! %v\n", globMatch)
	return findLicenses(c, resolver, globMatch, pathToCheck)
}

func requireCollection(licenses []pkg.License) []pkg.License {
	if licenses == nil {
		return make([]pkg.License, 0)
	}
	return licenses
}

func findLicenses(c *staticLicenses, resolver file.Resolver, globMatch string, pathToCheck string) (out []pkg.License, err error) {
	out = make([]pkg.License, 0)

	files, _ := os.ReadDir(pathToCheck)
	for _, fileToCheck := range files {
		fileName := fileToCheck.Name()

		for _, name := range lowercaseLicenseFiles() {
			if name == fileName {
				l := file.NewLocation(pathToCheck + fileName)

				//fmt.Printf("LICENSE FILENAME FOUND! %v\n", fileName)

				contents, err := resolver.FileContentsByLocation(l)
				if err != nil {
					return nil, err
				}
				parsed, err := licenses.Parse(contents, l)
				if err != nil {
					return nil, err
				}

				out = append(out, parsed...)
			}
		}

	}

	return
}
func lowercaseLicenseFiles() []string {
	fileNames := licenses.FileNames()
	for i := range fileNames {
		fileNames[i] = strings.ToLower(fileNames[i])
	}
	return fileNames
}
