package verifier

import (
	"crypto/tls"
	"crypto/x509"
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

func (v *FabricRegistryValidationService) ValidateVC(verifiableCredential *verifiable.Credential, verificationContext ValidationContext) (bool, error) {
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
	}

	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				RootCAs: caCertPool,
			},
		},
	}

	req, err := http.NewRequest("POST", v.verifierURI, nil) // Asume POST, ajusta según sea necesario
	if err != nil {
		logging.Log().Errorf("Failed to create request: %s", err)
		return false, err
	}

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
