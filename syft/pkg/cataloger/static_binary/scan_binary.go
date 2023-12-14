package static_binary

import (
	"bytes"
	"debug/elf"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"regexp"
	"strings"

	"github.com/anchore/syft/internal/log"
	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/pkg/cataloger/internal/unionreader"
)

type fileInfo struct {
	Name    string `json:"name"`
	System  string `json:"system"`
	Version string `json:"version"`
}

func scanFile(c *staticBinaryCataloger, reader unionreader.UnionReader, filename string) ([]byte, []string, error) {
	bi, err := io.ReadAll(reader)
	if err != nil {
		log.WithFields("file", filename, "error", err).Trace("unable to read binary")
		return bi, nil, err
	}
	br := bytes.NewReader(bi)
	e, err := elf.NewFile(br)
	if e != nil {

		symbols, err := e.ImportedLibraries()
		if err != nil {
			log.Debugf("unable to read elf binary: %s", err)
			symbols = nil
		}

		//noteSection will be the raw data pulled from the section
		noteSection := e.Section(".note.package")
		if noteSection != nil {
			notes, err := noteSection.Data()
			var metadata pkg.StaticBinaryPackageMetadata
			newerr := json.Unmarshal(notes, &metadata)
			if newerr != nil {
				log.Debugf("noteSection not nill, json didn't partse error")
			}
			if notes == nil {
				log.Debugf("unable to read .note.package")
			}

			return notes, symbols, err
		} else {
			//This file did not have a note.package section. We must infer info another way
			ver, system := fileNameTemplateVersionMatcher(c, filename)

			//System is the same thing as namespace in the metadata we send over
			data := fileInfo{
				Name:    filename,
				System:  system,
				Version: ver,
			}

			b, _ := json.Marshal(data)

			return b, symbols, err
		}
	}
	return nil, nil, err
}

func scanLibrary(c *staticBinaryCataloger, lib string) ([]byte, []string, error) {
	var f *os.File
	f, fileErr_ := getLibFile(c, lib)
	if fileErr_ != nil {
		fmt.Printf("Error: %v\n", fileErr_)
	}
	newUnionReader, _ := unionreader.GetUnionReader(f)
	libnotes, liblibs, err := scanFile(c, newUnionReader, lib)
	return libnotes, liblibs, err

}

func getLibFile(c *staticBinaryCataloger, symbol string) (*os.File, error) {
	var f *os.File
	var libPath string
	//First we should check currect directory
	libPath = "./"
	f, fileErr_ := os.Open(libPath + symbol)
	if fileErr_ != nil {
		//Next we try lib64
		libPath = "/lib64/"
		f, fileErr_ = os.Open(libPath + symbol)
		if fileErr_ != nil {
			//last we try the options path
			libPaths := c.licenses.opts.localSharedLibDir
			for _, libPath := range libPaths {
				f, fileErr_ = os.Open(libPath + symbol)
				if fileErr_ == nil {
					return f, fileErr_
				}
			}
		}

	}
	return f, fileErr_
}

func fileNameTemplateVersionMatcher(c *staticBinaryCataloger, filename string) (string, string) {

	//Make sure its an so file and find where that is in the string
	re := regexp.MustCompile(`\.so\.?`)
	loc := re.FindStringIndex(filename)
	if loc == nil {
		//TODO: Not a .so file. This means at this point we are scanning an unsupported binary or executable
		return "", ""
	}
	//Now get the filename without the extension
	loc = []int{0, len(filename)}
	fileNamePattern := strings.Split(filename[loc[0]:], ".so")[0]
	templates := c.licenses.opts.templates
	if templates != nil {
		for _, template := range templates {
			re := regexp.MustCompile(template.pattern)
			if re.MatchString(fileNamePattern) {
				return template.version, template.namespace
			}
		}
		//we finished the loop and didn't find a match.
		version, namespace := checkKnownPatterns(filename)
		return version, namespace

	} else {
		version, namespace := checkKnownPatterns(filename)

		return version, namespace
	}

}

func checkKnownPatterns(filename string) (string, string) {
	var namespace string
	loc := []int{0, len(filename)}
	fileNamePattern := strings.Split(filename[loc[0]:], ".so")[0]
	//Try to find our version after the .so in the filename first
	version := filename[strings.LastIndex(filename, ".")+1:]
	if version == "" {
		//Version wasn't a suffix. Now lets look for numbers
		//in the prefix of the filename
		re := regexp.MustCompile(`\d.*`)
		match := re.FindString(fileNamePattern)
		version = match
	}

	if fileNamePattern == "libactivemq-cpp" {
		namespace = "apache"
		return version, namespace
	}
	if fileNamePattern == "libstdc++" || fileNamePattern == "libm" || fileNamePattern == "libgcc_s" ||
		fileNamePattern == "libc" || fileNamePattern == "libdl" {
		namespace = "gnu"
		return version, namespace
	}
	if fileNamePattern == "libxerces-c-3.2" {
		version = "3.2"
		namespace = "apache"
		return version, namespace
	}
	if fileNamePattern == "libclntsh" {
		version = "19.1"
		namespace = "oracle"
		return version, namespace
	}
	if fileNamePattern == "libxalan-c" || fileNamePattern == "libxalanMsg" {
		version = "1.12"
		namespace = "apache"
		return version, namespace
	}
	if fileNamePattern == "libapr-1" {
		version = "1.6.3"
		namespace = "apache"
		return version, namespace
	}
	if fileNamePattern == "libssl" || fileNamePattern == "libcrypto" {
		version = "1.0.0"
		namespace = "openssl"
		return version, namespace
	}
	re := regexp.MustCompile("lib[a-z]{3}[0-9]*.")
	if re.MatchString(fileNamePattern) {
		version = "2022.1.1.2"
		namespace = "roguewave"
		return version, namespace
	}

	return version, namespace
}
