/*
GPget - A tool for securely retrieving files from hostile storage

Copyright (C) 2016 Brian 'redbeard' Harrington

This program is free software; you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation; either version 2 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program; if not, write to the Free Software
Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
*/

package main

import (
	"bytes"
	"code.google.com/p/go.crypto/openpgp"
	"code.google.com/p/go.crypto/openpgp/clearsign"
	"flag"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
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
	flagHelp  = flag.Bool("help", false, "print help and exit")
	flagURL   = flag.String("url", "", "url to retrieve")
	flagMem   = flag.Bool("O", false, "save the file using it's original name")
	flagPath  = flag.String("o", "./", "location to place successful download")
	flagKeyid = flag.String("k", "", "GPG key identity expected to be used for the remote file")
	flagBin   = flag.Bool("b", false, "Use a binary signature instead of armored ASCII")
	flagClear = flag.Bool("c", false, "Download the message as clearsigned armored ASCII")
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
	signature []byte
	content   []byte
}

type SigState struct {
	success bool
	sig     string
	content []byte
}

func main() {

	flag.Parse()

	if *flagHelp {
		flag.Usage()
		os.Exit(1)
	}

	gpfile, err := dlFile(*flagURL)

	if err != nil {
		fmt.Println("Failed to download file: %s", err)
		os.Exit(3)
	}

	state, err := checkGPG(&gpfile)
	if err != nil {
		fmt.Println("Failed to validate GPG signature: %s", err)
		os.Exit(3)
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
		fmt.Print(string(gpfile.content))
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
// form "url" + ".asc" or ".sig" representing the binary and base64 gpg
// signatures respectively

func dlFile(uri string) (file File, err error) {
	var myfile File
	var sig []byte
	var ext string
	u, err := url.Parse(uri)

	if err != nil {
		fmt.Printf("Error parsing the URL %s\n", uri)
		os.Exit(2)
	}

	myfile.name = path.Base(u.Path)
	myfile.content, err = getRemote(u.String())

	if err != nil {
		if err == http.ErrMissingFile {
			fmt.Printf("Error (404): the file %s did not exist\n", uri)
			os.Exit(1)
		} else {
			fmt.Printf("Transport error retreiving %s\n" + uri)
			os.Exit(1)
		}
	}

	if *flagBin {
		u.Path += ".sig"
	} else {
		u.Path += ".asc"
	}

	if !*flagClear {
		sig, err = getRemote(u.String())

		if err != nil {
			if err == http.ErrMissingFile {
				fmt.Printf("Error (404): the file %s did not exist, you must sign all files with an ASCII armored signature", ext)
				os.Exit(1)
			} else {
				fmt.Println("Transport error retreiving detached signature: ",
					ext)
				os.Exit(1)
			}
		}

		myfile.signature = sig
	}

	return myfile, nil
}

func checkGPG(file *File) (state SigState, err error) {
	var signer *openpgp.Entity
	var cs *clearsign.Block
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

	if *flagClear {
		cs, _ = clearsign.Decode(file.content)
		if cs == nil {
			fmt.Printf("Problem decoding clearsign signature from file %s\n", file.name)
			os.Exit(2)
		}

		lsig, err := ioutil.ReadAll(cs.ArmoredSignature.Body)

		if err != nil {
			fmt.Printf("Problem reading signature from %s.  Are you sure this file is clearsigned?: %s\n", file.name, err)
			os.Exit(2)
		}
		if len(lsig) > 0 {
			file.signature = lsig
			file.content = cs.Bytes
			*flagBin = true
		}

	}

	if *flagBin {
		signer, err = openpgp.CheckDetachedSignature(keyring, bytes.NewReader(file.content), bytes.NewReader(file.signature))
	} else {
		signer, err = openpgp.CheckArmoredDetachedSignature(keyring, bytes.NewReader(file.content), bytes.NewReader(file.signature))
	}
	if err != nil {
		fmt.Printf("Invalid signature or public key not present: %s\n", err)
		os.Exit(2)
	}

	state.sig = signer.PrimaryKey.KeyIdString()

	l := len(*flagKeyid)
	if l > 0 {
		var rid string

		// Force the local id to be all uppercase
		lid := strings.ToUpper(*flagKeyid)

		// check the number of chars on the remote id to see if it's a
		// short or long id. If it's not 8 or 16, it's not valid.
		switch l {
		case 8:
			rid = signer.PrimaryKey.KeyIdShortString()
		case 16:
			rid = signer.PrimaryKey.KeyIdString()
		}
		if len(rid) == 0 {
			fmt.Printf("You did not specify a valid GPG keyid length. Must be 8 or 16 characters.")
			os.Exit(2)
		}

		if lid != rid {
			fmt.Printf("The remote file was not signed by the expected GPG Public key. Expected %s and got %s\n", lid, rid)
			os.Exit(2)
		}
	}

	// Due to how clearsign works, the detached signature has to be
	// processed using the Bytes field, but the stripped content is located
	// in the Plaintext field. As we've verified the signature was valid
	// we can now fix the content

	if *flagClear {
		file.content = cs.Plaintext
	}

	state.success = true
	return state, nil
}
