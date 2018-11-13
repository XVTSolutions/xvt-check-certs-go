// Copyright 2013 Ryan Rogers. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"github.com/gorilla/mux"
	"log"
	"net/http"
	"strconv"
	"time"
)

const (
	errExpiringShortly = "%s: ** '%s' (S/N %X) expires in %d hours! **"
	errExpiringSoon    = "%s: '%s' (S/N %X) expires in roughly %d days."
	errSunsetAlg       = "%s: '%s' (S/N %X) expires after the sunset date for its signature algorithm '%s'."
)

type sigAlgSunset struct {
	name      string    // Human readable name of signature algorithm
	sunsetsAt time.Time // Time the algorithm will be sunset
}

var checkSigAlg = true

// sunsetSigAlgs is an algorithm to string mapping for signature algorithms
// which have been or are being deprecated.  See the following links to learn
// more about SHA1's inclusion on this list.
//
// - https://technet.microsoft.com/en-us/library/security/2880823.aspx
// - http://googleonlinesecurity.blogspot.com/2014/09/gradually-sunsetting-sha-1.html
var sunsetSigAlgs = map[x509.SignatureAlgorithm]sigAlgSunset{
	x509.MD2WithRSA: sigAlgSunset{
		name:      "MD2 with RSA",
		sunsetsAt: time.Now(),
	},
	x509.MD5WithRSA: sigAlgSunset{
		name:      "MD5 with RSA",
		sunsetsAt: time.Now(),
	},
	x509.SHA1WithRSA: sigAlgSunset{
		name:      "SHA1 with RSA",
		sunsetsAt: time.Date(2017, 1, 1, 0, 0, 0, 0, time.UTC),
	},
	x509.DSAWithSHA1: sigAlgSunset{
		name:      "DSA with SHA1",
		sunsetsAt: time.Date(2017, 1, 1, 0, 0, 0, 0, time.UTC),
	},
	x509.ECDSAWithSHA1: sigAlgSunset{
		name:      "ECDSA with SHA1",
		sunsetsAt: time.Date(2017, 1, 1, 0, 0, 0, 0, time.UTC),
	},
}

type certErrors struct {
	commonName string
	errs       []error
}

type hostResult struct {
	host  string
	err   error
	certs []certErrors
}

type JsonResponse struct {
	Name string `json:"name"`
	Message string `json:"message"`
}

type JsonResponses []JsonResponse

func main() {
	r:= mux.NewRouter()
	r.HandleFunc("/check/{host}/{days}", CertificateHandler)

	log.Fatal(http.ListenAndServe(":8000", r))
}

func CertificateHandler(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	warnDays, err := strconv.Atoi(vars["days"])

	if err != nil {
		panic(err)
	}

	result := checkHost(vars["host"], warnDays)

	w.WriteHeader(http.StatusOK)
	w.Header().Set("Content-Type", "application/json")

	if result.err != nil {
		json.NewEncoder(w).Encode(result.err)
	} else {
		var response JsonResponses
		for _, cert :=  range result.certs {
			for _, certErr := range cert.errs {
				response = append(response, JsonResponse{cert.commonName,certErr.Error()})
			}
		}
		json.NewEncoder(w).Encode(response)
	}
}

func checkHost(host string, warnDays int) (result hostResult) {
	result = hostResult{
		host:  host,
		certs: []certErrors{},
	}
	conn, err := tls.Dial("tcp", host, nil)
	if err != nil {
		result.err = err
		return
	}
	defer conn.Close()

	timeNow := time.Now()
	checkedCerts := make(map[string]struct{})
	for _, chain := range conn.ConnectionState().VerifiedChains {
		for certNum, cert := range chain {
			if _, checked := checkedCerts[string(cert.Signature)]; checked {
				continue
			}
			checkedCerts[string(cert.Signature)] = struct{}{}
			cErrs := []error{}

			// Check the expiration.
			if timeNow.AddDate(0, 0, warnDays).After(cert.NotAfter) {
				expiresIn := int64(cert.NotAfter.Sub(timeNow).Hours())
				if expiresIn <= 48 {
					cErrs = append(cErrs, fmt.Errorf(errExpiringShortly, host, cert.Subject.CommonName, cert.SerialNumber, expiresIn))
				} else {
					cErrs = append(cErrs, fmt.Errorf(errExpiringSoon, host, cert.Subject.CommonName, cert.SerialNumber, expiresIn/24))
				}
			}

			// Check the signature algorithm, ignoring the root certificate.
			if alg, exists := sunsetSigAlgs[cert.SignatureAlgorithm]; checkSigAlg && exists && certNum != len(chain)-1 {
				if cert.NotAfter.Equal(alg.sunsetsAt) || cert.NotAfter.After(alg.sunsetsAt) {
					cErrs = append(cErrs, fmt.Errorf(errSunsetAlg, host, cert.Subject.CommonName, cert.SerialNumber, alg.name))
				}
			}

			result.certs = append(result.certs, certErrors{
				commonName: cert.Subject.CommonName,
				errs:       cErrs,
			})
		}
	}

	return
}
