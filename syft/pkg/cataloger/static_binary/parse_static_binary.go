package static_binary

import (

	//"os"

	//"github.com/anchore/syft/internal"
	"encoding/json"
	"fmt"

	"github.com/anchore/syft/syft/artifact"
	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/pkg/cataloger/generic"
	"github.com/anchore/syft/syft/pkg/cataloger/internal/unionreader"
)

type staticBinaryCataloger struct {
	licenses staticLicenses
}

func (c *staticBinaryCataloger) parseStaticBinary(resolver file.Resolver, env *generic.Environment, reader file.LocationReadCloser) ([]pkg.Package, []artifact.Relationship, error) {

	var pkgs []pkg.Package
	myresolver, _ := resolver.FileContentsByLocation(reader.Location)
	unionReader, err := unionreader.GetUnionReader(myresolver)
	if err != nil {
		return nil, nil, err
	}
	// get our notes.package info and our shared libs
	notes, libs, _ := scanFile(c, unionReader, reader.RealPath)

	var metadata pkg.StaticBinaryPackageMetadata
	newerr := json.Unmarshal(notes, &metadata)
	if newerr != nil {
		fmt.Println("Something bad happened again:")
	}
	if metadata.Type == "static-binary" {
		pkgs = append(pkgs, c.buildBinaryPkgInfo(resolver, reader.Location, notes, libs)...)
	}
	if metadata.Type == "shared-library" {
		pkgs = append(pkgs, c.buildStaticLibPkgInfo(resolver, reader.Location, notes, libs)...)

	}

	return pkgs, nil, nil
}

func (c *staticBinaryCataloger) buildBinaryPkgInfo(resolver file.Resolver, location file.Location, notes []byte, libs []string) []pkg.Package {
	var pkgs []pkg.Package
	var libCache []string
	if notes == nil {
		return pkgs
	}

	scanDepth := c.licenses.opts.scanDepth
	currentDepth := 0

	p := c.newStaticBinaryPackage(
		resolver,
		libs,
		notes,
		location,
	)

	pkgs = append(pkgs, p)
	pkgs = append(pkgs, c.buildLibraryPkgInfo(resolver, libs, libCache, scanDepth, currentDepth, location, pkgs)...)

	return pkgs
}

func (c *staticBinaryCataloger) buildStaticLibPkgInfo(resolver file.Resolver, location file.Location, notes []byte, libs []string) []pkg.Package {
	var pkgs []pkg.Package
	var libCache []string
	if notes == nil {
		return pkgs
	}
	scanDepth := c.licenses.opts.scanDepth
	currentDepth := 0
	p := c.newStaticLibraryPackage(
		resolver,
		libs,
		notes,
		location,
	)

	pkgs = append(pkgs, p)
	pkgs = append(pkgs, c.buildLibraryPkgInfo(resolver, libs, libCache, scanDepth, currentDepth, location, pkgs)...)

	return pkgs
}

func (c *staticBinaryCataloger) buildLibraryPkgInfo(resolver file.Resolver, libs []string, libCache []string, scanDepth int, currentDepth int, location file.Location, pkgs []pkg.Package) []pkg.Package {
	//Base recursion test. Break out if we call this with no libs
	if libs == nil || currentDepth > scanDepth {
		return pkgs
	}

	for _, lib := range libs {

		//for each lib, first see if our cache has it already. If not, we should add it
		if !contains(libCache, lib) {

			//Add our lib to the cache
			libCache = append(libCache, lib)

			//Scan our lib and get package info and its own libs
			notes, deps, _ := scanLibrary(c, lib)

			//Create our lib struct for what we just found
			p := c.newStaticBinaryDepPackage(
				resolver,
				lib,
				deps,
				notes,
				location,
				pkgs[len(pkgs)-1].Licenses.ToSlice(),
			)

			// Append the package to the list
			pkgs = append(pkgs, p)
			// Call this function again in case our lib had dependencies
			if currentDepth <= scanDepth {
				//increment current depth
				currentDepth++
				pkgs = append(pkgs, c.buildLibraryPkgInfo(resolver, deps, libCache, scanDepth, currentDepth, location, pkgs)...)
			}
		}

		// if we have already added it, just continue with the loop.
	}
	return pkgs
}

func contains(s []string, str string) bool {
	for _, v := range s {
		if v == str {
			return true
		}
	}
	return false
}
