package verifier

import (
	"bytes"
	"encoding/json"
	"net/http"

	"github.com/fiware/VCVerifier/logging"
	"github.com/trustbloc/vc-go/verifiable"
)

type FabricRegistryValidationService struct {
	verifierURI string
}

// InitFabricRegistryValidationService inicializa el servicio de validación con la URI del verificador
func InitFabricRegistryValidationService(verifierURI string) *FabricRegistryValidationService {
	return &FabricRegistryValidationService{
		verifierURI: verifierURI,
	}
}

// CredentialRequest define la estructura para el cuerpo de la solicitud de validación
type CredentialRequest struct {
	Cred string `json:"cred"`
}

// ValidateVC envía la credencial verificable al servicio de validación
func (v *FabricRegistryValidationService) ValidateVC(
	verifiableCredential *verifiable.Credential,
	_ ValidationContext,
) (bool, error) {
	// Convierte la credencial a JSON
	credentialBytes, err := json.Marshal(verifiableCredential)
	if err != nil {
		logging.Log().Errorf("Failed to marshal verifiable credential: %s", err)
		return false, err
	}

	// Prepara el cuerpo de la petición
	credRequest := CredentialRequest{Cred: string(credentialBytes)}
	requestBody, err := json.Marshal(credRequest)
	if err != nil {
		logging.Log().Errorf("Failed to marshal credential request: %s", err)
		return false, err
	}

	// Usa cliente HTTP por defecto
	client := http.DefaultClient

	// Crea y envía la petición
	req, err := http.NewRequest("POST", v.verifierURI, bytes.NewBuffer(requestBody))
	if err != nil {
		logging.Log().Errorf("Failed to create request: %s", err)
		return false, err
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		logging.Log().Errorf("Failed to send request: %s", err)
		return false, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		logging.Log().Errorf("Validation failed with status: %s", resp.Status)
		return false, nil
	}

	return true, nil
}
