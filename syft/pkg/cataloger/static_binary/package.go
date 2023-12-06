package static_binary

import (
	"encoding/json"
	"fmt"

	"github.com/anchore/packageurl-go"
	"github.com/anchore/syft/internal/log"
	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/pkg"
)

func (c *staticBinaryCataloger) newStaticBinaryPackage(resolver file.Resolver, libs []string, notes []byte, location file.Location) pkg.Package {

	//Create and set a var to access our metadata
	var metadata pkg.StaticBinaryPackageMetadata
	newerr := json.Unmarshal(notes, &metadata)
	if newerr != nil {
		fmt.Println("Something bad happened again:")
	}
	//Get an array of licenses
	licenses, err := c.licenses.getLicenses(resolver, metadata.Name, location)
	if err != nil {
		log.Tracef("error getting licenses for static binary package: %s %v", metadata.Name, err)
	}

	//Construct the package

	p := pkg.Package{
		Name:      metadata.Name,
		Version:   metadata.Version,
		Licenses:  pkg.NewLicenseSet(licenses...),
		PURL:      packageURL(metadata.Name, metadata.System, metadata.Version),
		Language:  pkg.StaticBinary,
		Type:      pkg.StaticBinaryPkg,
		Locations: file.NewLocationSet(location),
		Metadata:  metadata,
	}

	p.SetID()

	return p

}
func (c *staticBinaryCataloger) newStaticLibraryPackage(resolver file.Resolver, libs []string, notes []byte, location file.Location) pkg.Package {
	//Create and set a var to access our metadata
	var metadata pkg.StaticBinaryLibraryMetadata
	newerr := json.Unmarshal(notes, &metadata)
	if newerr != nil {
		fmt.Println("Something bad happened again:")
	}
	//Get an array of licenses
	licenses, err := c.licenses.getLicenses(resolver, metadata.Name, location)
	if err != nil {
		log.Tracef("error getting licenses for static binary package: %s %v", metadata.Name, err)
	}

	//Construct the package

	p := pkg.Package{
		Name:      metadata.Name,
		Version:   metadata.Version,
		Licenses:  pkg.NewLicenseSet(licenses...),
		PURL:      packageURL(metadata.Name, metadata.System, metadata.Version),
		Language:  pkg.StaticBinary,
		Type:      pkg.StaticLibraryPkg,
		Locations: file.NewLocationSet(location),
		Metadata:  metadata,
	}

	p.SetID()

	return p

}
func (c *staticBinaryCataloger) newStaticBinaryDepPackage(resolver file.Resolver, lib string, deps []string, notes []byte, location file.Location, licenses []pkg.License) pkg.Package {

	//Create and set a var to access our metadata
	var metadata pkg.StaticBinaryLibraryMetadata
	newerr := json.Unmarshal(notes, &metadata)

	//TODO: Need to set parent and deps for metadata.

	if newerr != nil {
		fmt.Printf("Err: %v\n", newerr)

	}
	//Get an array of licenses
	//This should include licenses for 3rd party libs at this stage

	//We need to change this. It should just take what we've already found and send it along, not re-search for the license file again
	//licenses, err := c.licenses.getLicenses(resolver, metadata.Name, location)
	// if err != nil {
	// 	log.Tracef("error getting licenses for static binary package: %s %v", metadata.Name, err)
	// }

	//Construct the package

	p := pkg.Package{
		Name:      lib,
		Version:   metadata.Version,
		Licenses:  pkg.NewLicenseSet(licenses...),
		PURL:      packageURL(metadata.Name, metadata.System, metadata.Version),
		Language:  pkg.StaticBinary,
		Type:      pkg.StaticLibraryPkg,
		Locations: file.NewLocationSet(location),
		Metadata:  metadata,
	}

	p.SetID()

	return p

}

func packageURL(name string, namespace string, version string) string {

	return packageurl.NewPackageURL(
		packageurl.TypeGeneric,
		namespace,
		name,
		version,
		nil,
		"",
	).ToString()
}
