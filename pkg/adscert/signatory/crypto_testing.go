package signatory

import (
	"crypto/sha256"
	"encoding/base64"
	"fmt"

	"golang.org/x/crypto/curve25519"
)

func GenerateFakePrivateKeysForTesting(adscertCallsign string) []string {
	_, primaryPrivateKey := GenerateFakeKeyPairFromDomainNameForTesting("_delivery._adscert." + adscertCallsign)
	fmt.Println(base64.RawURLEncoding.EncodeToString(primaryPrivateKey[:]))
	if adscertCallsign == "ssai.tk" {
		return []string{"WnZgLV-AJTcFIYxzP-fytX7PVJviPcPBCzb9PxnjjzI"}
	} else {
		return []string{"Ayidgo7j5zxlfls_hFDozXTWT4QR2fcU3xvbmSreTKI"}
	}
	//return keys
	/*return []string{

		base64.RawURLEncoding.EncodeToString(primaryPrivateKey[:]),
	}*/

}

func GenerateFakeAdsCertRecordForTesting(adscertCallsign string) string {
	primaryPublicKey, _ := GenerateFakeKeyPairFromDomainNameForTesting(adscertCallsign)
	fmt.Println(base64.RawURLEncoding.EncodeToString(primaryPublicKey[:]))
	if adscertCallsign == "ssai.tk" {
		return fmt.Sprintf("v=adcrtd k=x25519 h=sha256 p=%s", "OEUzGdBiuwq1KjL2SOk54eChr5aXFSBn2ZL8n5DMT2Y") //base64.RawURLEncoding.EncodeToString(primaryPublicKey[:]),
	} else {
		return fmt.Sprintf("v=adcrtd k=x25519 h=sha256 p=%s", "4U1O8MMS2otLWm9QJsgMHe0c-5vj2Tx8FUXAFy3GAFU") //base64.RawURLEncoding.EncodeToString(primaryPublicKey[:]),
	}

}

func GenerateFakeKeyPairFromDomainNameForTesting(adscertCallsign string) ([32]byte, [32]byte) {
	privateKey := sha256.Sum256([]byte(adscertCallsign))
	var publicKey [32]byte
	curve25519.ScalarBaseMult(&publicKey, &privateKey)
	return publicKey, privateKey
}
