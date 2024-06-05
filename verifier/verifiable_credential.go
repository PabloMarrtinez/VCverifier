package verifier

import (
	"errors"
	"reflect"

	logging "github.com/fiware/VCVerifier/logging"
	"github.com/mitchellh/mapstructure"
	"golang.org/x/exp/slices"
)

// Subset of the structure of a Verifiable Credential
type VerifiableCredential struct {
	MappableVerifiableCredential
	raw map[string]interface{} // The unaltered complete credential
}

// TODO Issue fix to mapstructure to enable combination of "DecoderConfig.ErrorUnset" and an unmapped/untagged field
type MappableVerifiableCredential struct {
	Id                string            `mapstructure:"id"`
	Types             []string          `mapstructure:"type"`
	Issuer            string            `mapstructure:"issuer"`
	CredentialSubject CredentialSubject `mapstructure:"credentialSubject"`
}

// Subset of the structure of a CredentialSubject inside a Verifiable Credential
type CredentialSubject struct {
	Id          string                 `mapstructure:"id"`
	SubjectType string                 `mapstructure:"type"`
	Claims      map[string]interface{} `mapstructure:",remain"`
}

func optionalFields() []string {
	return []string{"credentialSubject.id", "credentialSubject.type"}
}

func (vc VerifiableCredential) GetCredentialType() string {
	return vc.CredentialSubject.SubjectType
}

func (vc VerifiableCredential) GetRawData() map[string]interface{} {
	return vc.raw
}

func (vc VerifiableCredential) GetIssuer() string {
	return vc.Issuer
}

func MapVerifiableCredential(raw map[string]interface{}) (VerifiableCredential, error) {
	var data MappableVerifiableCredential
	var metaData mapstructure.Metadata

	credentialSubjectArrayDecoder := func(from, to reflect.Type, data interface{}) (interface{}, error) {
		if to != reflect.TypeOf((*CredentialSubject)(nil)).Elem() {
			return data, nil
		}
		if reflect.TypeOf(data).Kind() != reflect.Slice {
			return data, nil
		}
		vcArray := data.([]interface{})
		if len(vcArray) > 0 {
			logging.Log().Warn("Found more than one credential subject. Will only use/validate first one.")
			return vcArray[0], nil
		} else {
			return []interface{}{}, nil
		}
	}

	config := &mapstructure.DecoderConfig{
		ErrorUnused:          false,
		Result:               &data,
		Metadata:             &metaData,
		ErrorUnset:           false,
		IgnoreUntaggedFields: true,
		DecodeHook:           credentialSubjectArrayDecoder,
	}
	decoder, err := mapstructure.NewDecoder(config)
	if err != nil {
		return VerifiableCredential{}, err
	}
	if err := decoder.Decode(raw); err != nil {
		return VerifiableCredential{}, err
	}

	for _, unsetField := range metaData.Unset {
		if !slices.Contains(optionalFields(), unsetField) {
			logging.Log().Warnf("%s is unset.", unsetField)
			return VerifiableCredential{}, errors.New("unset_field")
		}
	}

	return VerifiableCredential{data, raw}, nil
}
