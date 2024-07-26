package verifier

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"net/http"
	"os"

	"github.com/fiware/VCVerifier/logging"
	"github.com/trustbloc/vc-go/verifiable"
)

type FabricRegistryValidationService struct {
	verifierURI              string
	validationServerCertPath string
}

// Inicializa el servicio de validación eliminando los parámetros innecesarios
func InitFabricRegistryValidationService(verifierURI, validationServerCertPath string) *FabricRegistryValidationService {
	return &FabricRegistryValidationService{
		verifierURI:              verifierURI,
		validationServerCertPath: validationServerCertPath,
	}
}

// Define la estructura para el cuerpo de la solicitud
type CredentialRequest struct {
	Cred string `json:"cred"`
}

func (v *FabricRegistryValidationService) ValidateVC(verifiableCredential *verifiable.Credential, verificationContext ValidationContext) (bool, error) {
	// Convierte la credencial a JSON
	credentialBytes, err := json.Marshal(verifiableCredential)
	if err != nil {
		logging.Log().Errorf("Failed to marshal verifiable credential: %s", err)
		return false, err
	}

	// Crea la solicitud con el parámetro "cred"
	credRequest := CredentialRequest{
		Cred: string(credentialBytes),
	}

	// Convierte la solicitud a JSON
	requestBody, err := json.Marshal(credRequest)
	if err != nil {
		logging.Log().Errorf("Failed to marshal credential request: %s", err)
		return false, err
	}

	caCertPool := x509.NewCertPool()
	if v.validationServerCertPath != "" {
		caCert, err := os.ReadFile(v.validationServerCertPath)
		if err != nil {
			logging.Log().Errorf("Error loading server certificate: %s", err)
			return false, err
		}
		if !caCertPool.AppendCertsFromPEM(caCert) {
			logging.Log().Error("Error appending server certificate")
			return false, fmt.Errorf("error appending server certificate")
		}
	} else {
		logging.Log().Warn("No validation server certificate path provided")
	}

	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				RootCAs: caCertPool,
			},
		},
	}

	req, err := http.NewRequest("POST", v.verifierURI, bytes.NewBuffer(requestBody))
	if err != nil {
		logging.Log().Errorf("Failed to create request: %s", err)
		return false, err
	}
	req.Header.Set("Content-Type", "application/json")

	response, err := client.Do(req)
	if err != nil {
		logging.Log().Errorf("Failed to send request: %s", err)
		return false, err
	}
	defer response.Body.Close()

	if response.StatusCode != http.StatusOK {
		logging.Log().Errorf("Validation failed with status: %s", response.Status)
		return false, nil
	}

	return true, nil
}
