package main

import (
	"bytes"
	"code.google.com/p/go.crypto/openpgp"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"path"
	"strings"
)

/*
Define our various flags to be used in parsing CLI options.  The basic idea is
to provide the user with a minimal number of sane options.  The reality is that
as this is related to security, the user should likely be more involved in
understanding that they need to validate.  If this means specifying an explicit
GPG/PGP versus just assuming it's on the local keyring, so be it.
*/

var (
	flagHelp = flag.Bool("help", false, "print help and exit")
	flagURL  = flag.String("url", "", "url to retrieve")
	flagMem  = flag.Bool("O", false, "save the file using it's original name")
	flagPath = flag.String("o", "./", "location to place successful download")
)

/*
Define a struct to handle the file to be downloaded. As a part of this we define
fields related to verification of our file.  In the end this results in a single
data structure which SHOULD include at least one signature type:
  binary (signature)
  armor (base64)
A resulting File struct MAY include both types.  In this case the binary
signature takes precidence as per RFC 4880.
*/

type File struct {
	name      string
	armor     string
	signature []byte
	content   []byte
}

type SigState struct {
	success bool
	sig     string
}

func main() {

	flag.Parse()

	if *flagHelp {
		flag.Usage()
		os.Exit(1)
	}

	gpfile := dlFile(*flagURL)

	state, err := checkGPG(gpfile)
	if err != nil {
		log.Fatal(err)
	}
	if !state.success {
		fmt.Println("Unknown error in retrieving your file")
		os.Exit(3)
	}

	if *flagMem {
		f, err := os.Create(gpfile.name)
		if err != nil {
			fmt.Printf("Error opening file %s for write - %s", gpfile.name, err)
			os.Exit(5)
		}

		n, err := f.Write(gpfile.content)

		if err != nil {
			fmt.Printf("Unable to save file, %d bytes written of %d bytes total - %s\n", n, len(gpfile.content), err)
			os.Exit(5)
		}

	} else {
		fmt.Println(string(gpfile.content))
	}
	os.Exit(0)
}

// implements a simple function to retrieve a remote file, check for errors
// and return the byte stream

func getRemote(url string) (data []byte, err error) {
	resp, err := http.Get(url)

	if err != nil {
		fmt.Println("Could not download " + url)
		return data, err
	}

	if resp.StatusCode != http.StatusOK {
		fmt.Printf("Could not download the url %s\n", url)
		os.Exit(2)
	}

	data, err = ioutil.ReadAll(resp.Body)
	resp.Body.Close()

	return data, err
}

// download a specified file and look for a well formatted signature of the
// form "url" + ".asc" representing the binary and base64 gpg signatures
// respectively

func dlFile(url string) (file File) {
	var myfile File
	var err error
	var armor []byte
	asc := url + ".asc"

	myfile.name = path.Base(url)
	myfile.content, err = getRemote(url)

	if err != nil {
		if err == http.ErrMissingFile {
			fmt.Printf("Error (404): the file %s did not exist\n", url)
			os.Exit(1)
		} else {
			fmt.Printf("Transport error retreiving %s\n" + url)
			os.Exit(1)
		}
	}

	armor, err = getRemote(asc)

	if err != nil {
		if err == http.ErrMissingFile {
			fmt.Printf("Error (404): the file %s did not exist, you must sign all files with an ASCII armored signature", url+".asc")
			os.Exit(1)
		} else {
			fmt.Println("Transport error retreiving armored signature: " + url + ".asc")
			os.Exit(1)
		}
	}

	myfile.armor = string(armor)

	return myfile
}

func checkGPG(file File) (state SigState, err error) {
	keypath := path.Join(os.Getenv("HOME"), "/.gnupg/pubring.gpg")
	keys, err := os.Open(keypath)
	if err != nil {
		fmt.Printf("Could not open public keyring at %s\n", keypath)
		os.Exit(2)
	}

	keyring, err := openpgp.ReadKeyRing(keys)

	if err != nil {
		fmt.Printf("Error reading public keyring: %s\n", err)
		os.Exit(2)
	}

	signer, err := openpgp.CheckArmoredDetachedSignature(keyring, bytes.NewReader(file.content), strings.NewReader(file.armor))

	if err != nil {
		fmt.Printf("Invalid signature or public key not present: %s\n", err)
		os.Exit(2)
	}
	state.sig = signer.PrimaryKey.KeyIdShortString()
	state.success = true
	return state, nil
}
