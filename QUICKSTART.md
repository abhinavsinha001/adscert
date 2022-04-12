# Quick Start Guide for Local Testing

Build Binary
```
go mod download
go build
```

Generate test public-private key pair

`./adscert basicinsecurekeygen`

You will get output similar to this
```
Randomly generated key pair
Public key:  OEUzGdBiuwq1KjL2SOk54eChr5aXFSBn2ZL8n5DMT2Y
Private key: WnZgLV-AJTcFIYxzP-fytX7PVJviPcPBCzb9PxnjjzI
DNS TXT Entry: "v=adcrtd k=x25519 h=sha256 p=OEUzGdBiuwq1KjL2SOk54eChr5aXFSBn2ZL8n5DMT2Y"
```

Add this entry in your test domain for SSAI in DNS configuration tool.
e.g
|Name   | Type  | TTL  | Target  |
|---|---|---|---|
|_delivery._adscert.ssai.tk| TXT|3600 |v=adcrtd k=x25519 h=sha256 p=OEUzGdBiuwq1KjL2SOk54eChr5aXFSBn2ZL8n5DMT2Y|


Do the same for other parties 

```
Randomly generated key pair
Public key:  4U1O8MMS2otLWm9QJsgMHe0c-5vj2Tx8FUXAFy3GAFU
Private key: Ayidgo7j5zxlfls_hFDozXTWT4QR2fcU3xvbmSreTKI
DNS TXT Entry: "v=adcrtd k=x25519 h=sha256 p=4U1O8MMS2otLWm9QJsgMHe0c-5vj2Tx8FUXAFy3GAFU"
```

|Name   | Type  | TTL  | Target  |
|---|---|---|---|
|_delivery._adscert.exchange-pubm.ga| TXT|3600 |v=adcrtd k=x25519 h=sha256 p=4U1O8MMS2otLWm9QJsgMHe0c-5vj2Tx8FUXAFy3GAFU|


New exchange can use existing exchange as signing authority for that we can add new DNS entry
e.g if `exchange-new.ga` wants to delegate signing to `exchange-pubm.ga` then following policy needs to be added 

|Name   | Type  | TTL  | Target  |
|---|---|---|---|
|_adscert.exchange-new.ga| TXT|3600 |v=adpf a=exchange-pubm.ga|



Start the verifying server

```
go run examples/verifier-server/verifier-server.go -origin=exchange-pubm.ga
```

Start Signing server

Test for primary exchange
```
go run examples/signer-server/signer-server.go -frequency 5s --body '{"sample": "request"}' -origin=ssai.tk -url='http://exchange-pubm.ga:8090/request?param1=example&param2=another' -send_requests 
```

Test for secondry exchange where autority policy is applied
```
go run examples/signer-server/signer-server.go -frequency 5s --body '{"sample": "request"}' -origin=ssai.tk -url='http://exchange-new.ga:8090/request?param1=example&param2=another' -send_requests 
```
