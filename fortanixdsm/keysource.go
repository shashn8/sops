package fortanixdsm

import (
	"context"
	"encoding/base64"
	"fmt"
	"net/http"
	"os"
	"strings"
	"time"

	fortanix_client "github.com/fortanix/sdkms-client-go/sdkms"
	"github.com/getsops/sops/v3/logging"
	"github.com/sirupsen/logrus"
)

var (
	// log is the global logger for any FORTANIX DSM MasterKey.
	log *logrus.Logger
	// osHostname returns the hostname as reported by the kernel.
	osHostname = os.Hostname
)

func init() {
	log = logging.NewLogger("FORTANIXDSM")
}

type MasterKey struct {
	// UUID is the unique id used to refer to the fortanix dsm key.
	UUID         string
	EncryptedKey string
	CreationDate time.Time
}

func MasterKeysFromUUIDString(uuid string) []*MasterKey {
	var keys []*MasterKey
	if uuid == "" {
		return keys
	}
	for _, s := range strings.Split(uuid, ",") {
		keys = append(keys, NewMasterKeyFromUUID(s))
	}
	return keys
}

// NewMasterKeyFromUUID takes an UUID string and returns a new MasterKey for that
// ARN.
func NewMasterKeyFromUUID(uuid string) *MasterKey {
	key := &MasterKey{}
	uuid = strings.Replace(uuid, " ", "", -1)
	key.UUID = uuid
	key.CreationDate = time.Now().UTC()

	return key
}

// EncryptedDataKey returns the encrypted data key this master key holds
func (key *MasterKey) EncryptedDataKey() []byte {
	return []byte(key.EncryptedKey)
}

// SetEncryptedDataKey sets the encrypted data key for this master key
func (key *MasterKey) SetEncryptedDataKey(enc []byte) {
	key.EncryptedKey = string(enc)
}

// Encrypt takes a SOPS data key, encrypts it with Fortanix DSM and stores the result
// in the EncryptedKey field.
func (key *MasterKey) Encrypt(dataKey []byte) error {
	apiKey := os.Getenv("FORTANIX_API_KEY")
	endpoint := os.Getenv("FORTANIX_API_ENDPOINT")
	client := fortanix_client.Client{
		Endpoint:   endpoint,
		HTTPClient: http.DefaultClient,
	}
	ctx := context.Background()
	if apiKey == "" {
		log.Fatal("FORTANIX_API_KEY environment variable not set")
	}
	if endpoint == "" {
		log.Fatal("FORTANIX_API_ENDPOINT environment variable not set")
	}
	_, err := client.AuthenticateWithAPIKey(ctx, apiKey)
	if err != nil {
		log.WithField("uuid", key.UUID).Info("Encryption failed")
		return err
	}
	intnum := 128
	taglen := uint(intnum)
	sobj_id := &key.UUID
	encryptReq := fortanix_client.EncryptRequest{
		Plain:  dataKey,
		Alg:    fortanix_client.AlgorithmAes,
		Key:    fortanix_client.SobjectByID(*sobj_id),
		Mode:   fortanix_client.CryptModeSymmetric(fortanix_client.CipherModeGcm),
		TagLen: &taglen,
	}
	res, err := client.Encrypt(ctx, encryptReq)
	if err != nil {
		log.Printf("Encryption failed: %v", err)
	}

	tagstring := base64.StdEncoding.EncodeToString(*res.Tag)
	ivstring := base64.StdEncoding.EncodeToString(*res.Iv)
	cipherstring := base64.StdEncoding.EncodeToString(res.Cipher)
	key.EncryptedKey = base64.StdEncoding.EncodeToString([]byte(cipherstring + ":" + ivstring + ":" + tagstring))
	// key.EncryptedKey = base64.StdEncoding.EncodeToString(res.Cipher)
	log.WithField("uuid", key.UUID).Info("Encryption succeeded")
	return nil
}

// EncryptIfNeeded encrypts the provided sops' data key and encrypts it if it hasn't been encrypted yet
func (key *MasterKey) EncryptIfNeeded(dataKey []byte) error {
	if key.EncryptedKey == "" {
		return key.Encrypt(dataKey)
	}
	return nil
}

// Decrypt decrypts the EncryptedKey field with Fortanix DSM and returns the result.
func (key *MasterKey) Decrypt() ([]byte, error) {
	apiKey := os.Getenv("FORTANIX_API_KEY")
	endpoint := os.Getenv("FORTANIX_API_ENDPOINT")
	client := fortanix_client.Client{
		Endpoint:   endpoint,
		HTTPClient: http.DefaultClient,
	}
	ctx := context.Background()
	if apiKey == "" {
		log.Fatal("FORTANIX_API_KEY environment variable not set")
	}
	if endpoint == "" {
		log.Fatal("FORTANIX_API_ENDPOINT environment variable not set")
	}
	_, err := client.AuthenticateWithAPIKey(ctx, apiKey)
	if err != nil {
		log.WithField("uuid", key.UUID).Info("Decryption failed")
		return nil, err
	}
	decrypted_enc, err := base64.StdEncoding.DecodeString(key.EncryptedKey)
	if err != nil {
		log.WithField("uuid", key.UUID).Info("Decryption failed")
		return nil, fmt.Errorf("error base64-decoding encrypted information: %s", err)
	}

	cipher_iv_tag := strings.Split(string(decrypted_enc), ":")

	k, err := base64.StdEncoding.DecodeString(cipher_iv_tag[0])
	iv, err := base64.StdEncoding.DecodeString(cipher_iv_tag[1])
	tag, err := base64.StdEncoding.DecodeString(cipher_iv_tag[2])

	decryptReq := fortanix_client.DecryptRequest{
		Cipher: k,
		Key:    fortanix_client.SobjectByID(*&key.UUID),
		Mode:   fortanix_client.CryptModeSymmetric(fortanix_client.CipherModeGcm),
		Iv:     &iv,
		Tag:    &tag,
	}
	decrypted, err := client.Decrypt(ctx, decryptReq)
	if err != nil {
		log.WithField("arn", key.UUID).Info("Decryption failed")
		return nil, fmt.Errorf("failed to decrypt sops data key with Fortanix DSM: %w", err)
	}
	log.WithField("uuid", key.UUID).Info("Decryption succeeded")

	return decrypted.Plain, nil
}

// NeedsRotation returns whether the data key needs to be rotated or not.
func (key *MasterKey) NeedsRotation() bool {
	return time.Since(key.CreationDate) > (time.Hour * 24 * 30 * 6)
}

// ToString converts the key to a string representation
func (key *MasterKey) ToString() string {
	return key.UUID
}

// ToMap converts the MasterKey to a map for serialization purposes
func (key MasterKey) ToMap() map[string]interface{} {
	out := make(map[string]interface{})
	out["uuid"] = key.UUID
	out["created_at"] = key.CreationDate.UTC().Format(time.RFC3339)
	out["enc"] = key.EncryptedKey
	return out
}
