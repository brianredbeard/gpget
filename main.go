package main

import (
	"code.google.com/p/go.crypto/openpgp"
	"flag"
	"fmt"
	//	"io"
	"io/ioutil"
	"net/http"
	"os"
	"strconv"
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
	flagMem  = flag.Bool("mem", false, "keep the download buffer in memory")
	flagPath = flag.String("path", "./", "location to place successful download")
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

func main() {

	flag.Parse()

	if *flagHelp {
		flag.Usage()
		os.Exit(1)
	}

	thing := dlFile(*flagURL)

	fmt.Println(strconv.Itoa(len(thing.content)))
	os.Exit(0)
}

// implements a simple function to retrieve a remote file, check for errors
// and return the byte stream

func getRemote(url string) (data []byte, err error) {
	/* getRemote(
	 */
	resp, err := http.Get(url)
	if err != nil {
		fmt.Println("Could not download " + url)
		return data, err
	}

	data, err = ioutil.ReadAll(resp.Body)

	return data, err
}

// download a specified file and look for two well formatted signatures of the
// form "url" + ".sig" & "url" + ".asc" representing the binary and base64 gpg
// signatures respectively

func dlFile(url string) (file File) {
	var myfile File
	var err error
	var armor []byte
	fmt.Println("Downloading File")
	asc := url + ".asc"
	sig := url + ".sig"

	myfile.content, err = getRemote(url)
	armor, err = getRemote(asc)
	myfile.armor = string(armor)
	myfile.signature, err = getRemote(sig)

	if err != nil {
		if err == http.ErrMissingFile {
			fmt.Println("no armor file")
		} else {
			fmt.Println("Error retreiving armored signature: " + url + ".asc")
			os.Exit(1)
		}
	}

	return myfile
}

func checkGPG(file File) {
	keys, _ := os.Open("~/.gnupg/pubring.gpg")
	keyring, _ := openpgp.ReadKeyRing(keys)

	fmt.Println("%T : %#v\n", keyring, keyring)
	//signer, err := openpgp.CheckArmoredDetachedSignature(keyring, file.content, io.Reader(file.signature))
}
