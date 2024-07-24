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
	keySpec     types.KeySpec
	publicKey   crypto.PublicKey
	publicKeyMu sync.RWMutex
}

func NewPrivateKey(ctx context.Context, client *kms.Client, keyId string) (*PrivateKey, error) {
	output, err := client.DescribeKey(ctx, &kms.DescribeKeyInput{KeyId: aws.String(keyId)})
	if err != nil {
		return nil, err
	}
	key := &PrivateKey{
		ctx:     ctx,
		client:  client,
		keyId:   keyId,
		keySpec: output.KeyMetadata.KeySpec,
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
	algo, err := priv.chooseSigningAlgorithm(opts)
	if err != nil {
		return nil, err
	}
	output, err := priv.client.Sign(priv.ctx, &kms.SignInput{
		KeyId:            aws.String(priv.keyId),
		Message:          digest,
		SigningAlgorithm: algo,
		MessageType:      types.MessageTypeDigest,
	})
	if err != nil {
		return nil, err
	}
	return output.Signature, nil
}

func (priv *PrivateKey) chooseSigningAlgorithm(opts crypto.SignerOpts) (types.SigningAlgorithmSpec, error) {
	hashFunc := opts.HashFunc()
	switch priv.keySpec {
	case types.KeySpecRsa2048, types.KeySpecRsa3072, types.KeySpecRsa4096:
		switch hashFunc {
		case crypto.SHA256:
			return types.SigningAlgorithmSpecRsassaPkcs1V15Sha256, nil
		case crypto.SHA384:
			return types.SigningAlgorithmSpecRsassaPkcs1V15Sha384, nil
		case crypto.SHA512:
			return types.SigningAlgorithmSpecRsassaPkcs1V15Sha512, nil
		default:
			return "", fmt.Errorf("unsupported combination of key spec and hash func: %s, %s", priv.keySpec, hashFunc)
		}
	case types.KeySpecEccNistP256, types.KeySpecEccNistP384, types.KeySpecEccNistP521:
		switch hashFunc {
		case crypto.SHA256:
			return types.SigningAlgorithmSpecEcdsaSha256, nil
		case crypto.SHA384:
			return types.SigningAlgorithmSpecEcdsaSha384, nil
		case crypto.SHA512:
			return types.SigningAlgorithmSpecEcdsaSha512, nil
		default:
			return "", fmt.Errorf("unsupported combination of key spec and hash func: %s, %s", priv.keySpec, hashFunc)
		}
	default:
		return "", fmt.Errorf("unsupported key spec: %s", priv.keySpec)
	}
}
