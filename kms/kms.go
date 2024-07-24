package kms

import (
	"context"
	"crypto"
	"crypto/x509"
	"fmt"
	"io"
	"log"
	"sync"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/aws/aws-sdk-go-v2/service/kms/types"
)

type PrivateKey struct {
	ctx         context.Context
	client      *kms.Client
	keyId       string
	publicKey   crypto.PublicKey
	publicKeyMu sync.RWMutex
}

func NewPrivateKey(ctx context.Context, client *kms.Client, keyId string) (*PrivateKey, error) {
	key := &PrivateKey{
		ctx:    ctx,
		client: client,
		keyId:  keyId,
	}
	return key, nil
}

func (priv *PrivateKey) Public() crypto.PublicKey {
	// Check for a cached key.
	priv.publicKeyMu.RLock()
	if priv.publicKey != nil {
		priv.publicKeyMu.RUnlock()
		return priv.publicKey
	}
	priv.publicKeyMu.RUnlock()

	// Download the public key from KMS.
	output, err := priv.client.GetPublicKey(priv.ctx, &kms.GetPublicKeyInput{
		KeyId: aws.String(priv.keyId),
	})
	if err != nil {
		log.Printf("generate_cert: failed to retrieve public key from KMS: %v", err)
		return nil
	}

	// Try both methods for parsing X.509 public keys.
	var key crypto.PublicKey
	if key, err = x509.ParsePKIXPublicKey(output.PublicKey); err != nil {
		if key, err = x509.ParsePKCS1PublicKey(output.PublicKey); err != nil {
			log.Printf("generate_cert: failed to parse public key, invalid format")
			return nil
		}
	}

	// Cache the key for subsequent calls.
	priv.publicKeyMu.Lock()
	priv.publicKey = key
	priv.publicKeyMu.Unlock()

	return key
}

func (priv *PrivateKey) Sign(rand io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	output, err := priv.client.Sign(priv.ctx, &kms.SignInput{
		KeyId:            aws.String(priv.keyId),
		Message:          digest,
		SigningAlgorithm: types.SigningAlgorithmSpecRsassaPkcs1V15Sha256,
		MessageType:      types.MessageTypeDigest,
	})
	if err != nil {
		return nil, err
	}
	return output.Signature, nil
}

func chooseSigningAlgorithm(opts crypto.SignerOpts) (types.SigningAlgorithmSpec, error) {
	hashFunc := opts.HashFunc()
	switch hashFunc {
	case crypto.SHA256:
		return types.SigningAlgorithmSpecEcdsaSha256, nil
	case crypto.SHA384:
		return types.SigningAlgorithmSpecEcdsaSha384, nil
	case crypto.SHA512:
		return types.SigningAlgorithmSpecEcdsaSha512, nil
	default:
		return "", fmt.Errorf("unsupported hash func: %s", hashFunc)
	}
}
