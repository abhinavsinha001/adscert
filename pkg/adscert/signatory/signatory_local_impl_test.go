package signatory_test

import (
	crypto_rand "crypto/rand"
	"encoding/base64"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/IABTechLab/adscert/pkg/adscert/api"
	"github.com/IABTechLab/adscert/pkg/adscert/discovery"
	"github.com/IABTechLab/adscert/pkg/adscert/logger"
	"github.com/IABTechLab/adscert/pkg/adscert/signatory"
	"github.com/benbjohnson/clock"
)

func BenchmarkVerifyAuthenticatedConnection(b *testing.B) {
	var log = "exchange-pubm.ga,from=ssai.tk&from_key=OEUzGd&invoking=exchange-pubm.ga&nonce=rs2dBHHZroMj&status=1&timestamp=220412T094123&to=exchange-pubm.ga&to_key=4U1O8M; sigb=CrBS2Wm5WcBz&sigu=MYNLLXxQmaCS,WvkR/RrHe3fl+FEY0a/K74RLAfuvLMMd4ajbQmlselg=,oXmnYDIo8CDOmIrJged0PxqnYvlGREccLZcjkDoES24="
	var logInvalid = "exchange-pubm.ga,from=ssai.tk&from_key=OEUzGU&invoking=exchange-pubm.ga&nonce=rs2dBHHZroMj&status=1&timestamp=220412T094123&to=exchange-pubm.ga&to_key=4U1O8P; sigb=CrBS2Wm5WcBz&sigu=MYNLLXxQmaCS,WvkR/RrHe3fl+FEY0a/K74RLAfuvLMMd4ajbQmlselg=,oXmnYDIo8CDOmIrJged0PxqnYvlGREccLZcjkDoES24="

	req, err := parseLog(log)
	fmt.Printf("%+v\n", req)
	if err != nil {
		b.Errorf("Error parsing log: %s", err)
		return
	}
	reqInvalid, err := parseLog(logInvalid)
	fmt.Printf("%+v\n", req)
	if err != nil {
		b.Errorf("Error parsing log: %s", err)
		return
	}
	origin := req.GetRequestInfo()[0].GetInvokingDomain() //"exchange-pubm.ga"

	base64PrivateKeys := signatory.GenerateFakePrivateKeysForTesting(origin)

	signatoryApi := signatory.NewLocalAuthenticatedConnectionsSignatory(
		origin,
		crypto_rand.Reader,
		clock.New(),
		discovery.NewDefaultDnsResolver(),
		discovery.NewDefaultDomainStore(),
		time.Duration(30*time.Second), // domain check interval
		time.Duration(30*time.Second), // domain renewal interval
		base64PrivateKeys)

	_, err = signatoryApi.VerifyAuthenticatedConnection(req)
	if err != nil {
		b.Errorf("Error %s", err)
		return
	}
	//t.Errorf("Signed Object %s", sign)
	time.Sleep(5 * time.Second)
	b.ResetTimer()
	b.Run("VALID=1", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			sign, err := signatoryApi.VerifyAuthenticatedConnection(req)
			if err != nil {
				b.Errorf("Error %s", err)
			} else if sign.GetVerificationInfo()[0].GetSignatureDecodeStatus()[0] == api.SignatureDecodeStatus_SIGNATURE_DECODE_STATUS_BODY_AND_URL_VALID {
			} else {
				b.Errorf("Signed Object %s", sign)
			}
		}

	})

	b.Run("VALID=0", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			sign, err := signatoryApi.VerifyAuthenticatedConnection(reqInvalid)
			if err != nil {
				b.Errorf("Error %s", err)
			} else if sign.GetVerificationInfo()[0].GetSignatureDecodeStatus()[0] == api.SignatureDecodeStatus_SIGNATURE_DECODE_STATUS_INVALID_SIGNATURE {
			} else {
				b.Errorf("Signed Object %s", sign)
			}
		}

	})

}

func TestVerifyAuthenticatedConnection(t *testing.T) {
	var log = "exchange-pubm.ga,from=ssai.tk&from_key=OEUzGd&invoking=exchange-pubm.ga&nonce=rs2dBHHZroMj&status=1&timestamp=220412T094123&to=exchange-pubm.ga&to_key=4U1O8M; sigb=CrBS2Wm5WcBz&sigu=MYNLLXxQmaCS,WvkR/RrHe3fl+FEY0a/K74RLAfuvLMMd4ajbQmlselg=,oXmnYDIo8CDOmIrJged0PxqnYvlGREccLZcjkDoES24="

	req, err := parseLog(log)
	fmt.Printf("%+v\n", req)
	if err != nil {
		t.Errorf("Error parsing log: %s", err)
		return
	}
	origin := req.GetRequestInfo()[0].GetInvokingDomain() //"exchange-pubm.ga"

	base64PrivateKeys := signatory.GenerateFakePrivateKeysForTesting(origin)
	signatoryApi := signatory.NewLocalAuthenticatedConnectionsSignatory(
		origin,
		crypto_rand.Reader,
		clock.New(),
		discovery.NewDefaultDnsResolver(),
		discovery.NewDefaultDomainStore(),
		time.Duration(30*time.Second), // domain check interval
		time.Duration(30*time.Second), // domain renewal interval
		base64PrivateKeys)

	_, err = signatoryApi.VerifyAuthenticatedConnection(req)
	if err != nil {
		t.Errorf("Error %s", err)
		return
	}
	//t.Errorf("Signed Object %s", sign)
	time.Sleep(5 * time.Second)

	t.Run("VALID=1", func(t *testing.T) {

		sign, err := signatoryApi.VerifyAuthenticatedConnection(req)
		if err != nil {
			t.Errorf("Error %s", err)
		} else if sign.GetVerificationInfo()[0].GetSignatureDecodeStatus()[0] == api.SignatureDecodeStatus_SIGNATURE_DECODE_STATUS_BODY_AND_URL_VALID {
		} else {
			t.Errorf("Signed Object %s", sign)
		}

	})

}

func TestSignAuthenticatedConnection(t *testing.T) {
	reqInfo := &api.RequestInfo{}
	destinationUrl := "http://exchange-pubm.ga:8090/request?param1=example&param2=another"
	body := "{\"sample\": \"request\"}"
	err := signatory.SetRequestInfo(reqInfo, destinationUrl, []byte(body))
	if err != nil {
		fmt.Errorf("error parsing request info: %v", err)
		return
	}
	origin := "exchange-demo.ga"
	base64PrivateKeys := signatory.GenerateFakePrivateKeysForTesting(origin)

	signatoryApi := signatory.NewLocalAuthenticatedConnectionsSignatory(
		origin,
		crypto_rand.Reader,
		clock.New(),
		discovery.NewDefaultDnsResolver(),
		discovery.NewDefaultDomainStore(),
		time.Duration(30*time.Second), // domain check interval
		time.Duration(30*time.Second), // domain renewal interval
		base64PrivateKeys)

	signatureResponse, err := signatoryApi.SignAuthenticatedConnection(
		&api.AuthenticatedConnectionSignatureRequest{
			RequestInfo: reqInfo,
			Timestamp:   "",
			Nonce:       "",
		})

	if err != nil {
		logger.Warningf("unable to sign message (continuing...): %v", err)
	}
	time.Sleep(5 * time.Second)
	t.Run("VALID=1", func(t *testing.T) {

		signatureResponse, err = signatoryApi.SignAuthenticatedConnection(
			&api.AuthenticatedConnectionSignatureRequest{
				RequestInfo: reqInfo,
				Timestamp:   "",
				Nonce:       "",
			})
		if err != nil {
			t.Errorf("Error %s", err)
		} else {
			logger.Infof(signatory.GetSignatures(signatureResponse)[0])
			logger.Infof("Requesting URL %s with signature %s", destinationUrl, signatureResponse)
		}

	})

}

func BenchmarkSignAuthenticatedConnection(b *testing.B) {
	reqInfo := &api.RequestInfo{}
	destinationUrl := "http://exchange-pubm.ga:8090/request?param1=example&param2=another"
	body := "{\"sample\": \"request\"}"
	err := signatory.SetRequestInfo(reqInfo, destinationUrl, []byte(body))
	if err != nil {
		fmt.Errorf("error parsing request info: %v", err)
		return
	}
	origin := "exchange-demo.ga"
	base64PrivateKeys := signatory.GenerateFakePrivateKeysForTesting(origin)

	signatoryApi := signatory.NewLocalAuthenticatedConnectionsSignatory(
		origin,
		crypto_rand.Reader,
		clock.New(),
		discovery.NewDefaultDnsResolver(),
		discovery.NewDefaultDomainStore(),
		time.Duration(120*time.Second), // domain check interval
		time.Duration(120*time.Second), // domain renewal interval
		base64PrivateKeys)
	signReq := &api.AuthenticatedConnectionSignatureRequest{
		RequestInfo: reqInfo,
		Timestamp:   "",
		Nonce:       "",
	}
	signatureResponse, err := signatoryApi.SignAuthenticatedConnection(signReq)

	if err != nil {
		logger.Warningf("unable to sign message (continuing...): %v", err)
	}
	time.Sleep(5 * time.Second)
	b.Run("VALID=1", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			signReq := &api.AuthenticatedConnectionSignatureRequest{
				RequestInfo: reqInfo,
				Timestamp:   "",
				Nonce:       "",
			}
			signatureResponse, err = signatoryApi.SignAuthenticatedConnection(signReq)
			if err != nil {
				b.Errorf("Error %s", err)
			} else {
				logger.Debugf(signatory.GetSignatures(signatureResponse)[0])
				logger.Debugf("Requesting URL %s with signature %s", destinationUrl, signatureResponse)
			}
		}

	})

}

func parseLog(log string) (*api.AuthenticatedConnectionVerificationRequest, error) {
	parsedLog := strings.Split(log, ",")

	invokingDomain := parsedLog[0]
	signatureHeader := parsedLog[1]
	hashedRequestBodyBytes, err := base64.StdEncoding.DecodeString(parsedLog[2])
	if err != nil {
		return nil, err
	}
	hashedDestinationURLBytes, err := base64.StdEncoding.DecodeString(parsedLog[3])
	if err != nil {
		return nil, err
	}

	reqInfo := &api.RequestInfo{
		InvokingDomain: invokingDomain,
		UrlHash:        hashedDestinationURLBytes[:32],
		BodyHash:       hashedRequestBodyBytes[:32],
	}
	signatory.SetRequestSignatures(reqInfo, []string{signatureHeader})

	return &api.AuthenticatedConnectionVerificationRequest{RequestInfo: []*api.RequestInfo{reqInfo}}, nil
}
