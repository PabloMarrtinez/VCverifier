package verifier

import (
	"reflect"
	"testing"

	json2 "encoding/json"
)

var exampleCredential = map[string]interface{}{
	"@context": []string{
		"https://www.w3.org/2018/credentials/v1",
		"https://happypets.fiware.io/2022/credentials/employee/v1",
	},
	"id": "https://happypets.fiware.io/credential/25159389-8dd17b796ac0",
	"type": []string{
		"VerifiableCredential",
		"CustomerCredential",
	},
	"issuer":         "did:key:verifier",
	"issuanceDate":   "2022-11-23T15:23:13Z",
	"validFrom":      "2022-11-23T15:23:13Z",
	"expirationDate": "2032-11-23T15:23:13Z",
	"credentialSubject": map[string]interface{}{
		"id":     "someId",
		"target": "did:ebsi:packetdelivery",
		"type":   "gx:compliance",
	},
}

var exampleEmptySubjectCredential = map[string]interface{}{
	"@context": []string{
		"https://www.w3.org/2018/credentials/v1",
		"https://happypets.fiware.io/2022/credentials/employee/v1",
	},
	"id": "https://happypets.fiware.io/credential/25159389-8dd17b796ac0",
	"type": []string{
		"VerifiableCredential",
		"CustomerCredential",
	},
	"issuer":            "did:key:verifier",
	"issuanceDate":      "2022-11-23T15:23:13Z",
	"validFrom":         "2022-11-23T15:23:13Z",
	"expirationDate":    "2032-11-23T15:23:13Z",
	"credentialSubject": map[string]interface{}{},
}

var exampleNoIdCredential = map[string]interface{}{
	"@context": []string{
		"https://www.w3.org/2018/credentials/v1",
		"https://happypets.fiware.io/2022/credentials/employee/v1",
	},
	"type": []string{
		"VerifiableCredential",
		"CustomerCredential",
	},
	"issuer":            "did:key:verifier",
	"issuanceDate":      "2022-11-23T15:23:13Z",
	"validFrom":         "2022-11-23T15:23:13Z",
	"expirationDate":    "2032-11-23T15:23:13Z",
	"credentialSubject": map[string]interface{}{},
}

var exampleCredentialArraySubject = map[string]interface{}{
	"@context": []string{
		"https://www.w3.org/2018/credentials/v1",
		"https://happypets.fiware.io/2022/credentials/employee/v1",
	},
	"id": "https://happypets.fiware.io/credential/25159389-8dd17b796ac0",
	"type": []string{
		"VerifiableCredential",
		"CustomerCredential",
	},
	"issuer":         "did:key:verifier",
	"issuanceDate":   "2022-11-23T15:23:13Z",
	"validFrom":      "2022-11-23T15:23:13Z",
	"expirationDate": "2032-11-23T15:23:13Z",
	"credentialSubject": []interface{}{map[string]interface{}{
		"id":     "someId",
		"target": "did:ebsi:packetdelivery",
		"type":   "gx:compliance",
	},
	},
}

// Uses generated credential from https://compliance.lab.gaia-x.eu/development/docs/#/credential-offer/CommonController_issueVC
func getComplianceVCFromJson() map[string]interface{} {
	jsonStr := `{
		"@context": [
		  "https://www.w3.org/2018/credentials/v1",
		  "http://gx-registry-development:3000/development/api/trusted-shape-registry/v1/shapes/jsonld/trustframework#"
		],
		"type": [
		  "VerifiableCredential"
		],
		"id": "https://storage.gaia-x.eu/credential-offers/b3e0a068-4bf8-4796-932e-2fa83043e203",
		"issuer": "did:web:compliance.lab.gaia-x.eu:development",
		"issuanceDate": "2023-04-24T13:09:41.885Z",
		"expirationDate": "2023-07-23T13:09:41.885Z",
		"credentialSubject": [
		  {
			"type": "gx:compliance",
			"id": "did:web:raw.githubusercontent.com:egavard:payload-sign:master",
			"integrity": "sha256-9fc56e0099742e57d467156c4526ba723981b2e91eb0ccf6b725ec65b968fcc8"
		  }
		],
		"proof": {
		  "type": "JsonWebSignature2020",
		  "created": "2023-04-24T13:09:42.564Z",
		  "proofPurpose": "assertionMethod",
		  "jws": "eyJhbGciOiJQUzI1NiIsImI2NCI6ZmFsc2UsImNyaXQiOlsiYjY0Il19..FqKjKBWDrfYnFxbZ1TbJYBir0mwy_dya0yO2EGATlHJHD8m9G6fuiKXGYiCnEwGbe81jGKYWzUuq43if8klpszJ8EXmqIVMBHBJWymIrHD9bD4-P4uhx6TqZdkRXvvLUUkjpvOc_JdrntOCIpxNN68yV7NqKHKdRV_rbp4wIstdbCuyZdlAuGHuIow9iEOIfS4-9hdunDh-LBYcI7Mb6NePaKi48tJmO2HDiN3ysYJ15yQ-Pb5dfJtaQCq2o2QJ9ayu2kV4SQHoobMJrBESskQLdLGW_LIPFMRMiRQhE4vYytm61nuFcCTNc9ZHNVzWwOupSpYW3w0YjXQ_xZxH0TQ",
		  "verificationMethod": "did:web:compliance.lab.gaia-x.eu:development"
		}
	  }`
	x := map[string]interface{}{}

	json2.Unmarshal([]byte(jsonStr), &x)
	return x
}

func TestActualComplianceCredential(t *testing.T) {
	_, err := MapVerifiableCredential(getComplianceVCFromJson())

	if err != nil {
		t.Errorf("MapVerifiableCredential() error = %v", err)
		return
	}
}

func TestMapVerifiableCredential(t *testing.T) {
	type args struct {
		raw map[string]interface{}
	}
	tests := []struct {
		name    string
		args    args
		want    VerifiableCredential
		wantErr bool
	}{
		{
			"ValidCredential",
			args{exampleCredential},
			VerifiableCredential{
				MappableVerifiableCredential{
					Id: "https://happypets.fiware.io/credential/25159389-8dd17b796ac0",
					Types: []string{
						"VerifiableCredential",
						"CustomerCredential",
					},
					Issuer: "did:key:verifier",
					CredentialSubject: CredentialSubject{
						Id:          "someId",
						SubjectType: "gx:compliance",
						Claims:      map[string]interface{}{"target": "did:ebsi:packetdelivery"},
					},
				},
				exampleCredential,
			},
			false,
		},
		{
			"ValidCredentialWithEmptySubject",
			args{exampleEmptySubjectCredential},
			VerifiableCredential{
				MappableVerifiableCredential{
					Id: "https://happypets.fiware.io/credential/25159389-8dd17b796ac0",
					Types: []string{
						"VerifiableCredential",
						"CustomerCredential",
					},
					Issuer:            "did:key:verifier",
					CredentialSubject: CredentialSubject{},
				},
				exampleEmptySubjectCredential,
			},
			false,
		},
		{
			"ValidCertificateArraySubject",
			args{exampleCredentialArraySubject},
			VerifiableCredential{
				MappableVerifiableCredential{
					Id: "https://happypets.fiware.io/credential/25159389-8dd17b796ac0",
					Types: []string{
						"VerifiableCredential",
						"CustomerCredential",
					},
					Issuer: "did:key:verifier",
					CredentialSubject: CredentialSubject{
						Id:          "someId",
						SubjectType: "gx:compliance",
						Claims:      map[string]interface{}{"target": "did:ebsi:packetdelivery"},
					},
				},
				exampleCredentialArraySubject,
			},
			false,
		},
		{
			"InvalidCredential",
			args{map[string]interface{}{"someThing": "else"}},
			VerifiableCredential{},
			true,
		},
		{
			"NoIdCredential",
			args{exampleNoIdCredential},
			VerifiableCredential{},
			true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := MapVerifiableCredential(tt.args.raw)
			if (err != nil) != tt.wantErr {
				t.Errorf("MapVerifiableCredential() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("MapVerifiableCredential() = %v, want %v", got, tt.want)
			}
		})
	}
}
