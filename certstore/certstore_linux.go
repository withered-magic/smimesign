package certstore

import (
	"context"
	"crypto"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"log"

	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	svckms "github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/github/smimesign/kms"
)

const (
	certData = "<ADD_CERTIFICATE_HERE>"
	kmsKeyId = "<ADD_KMS_KEY_ID_HERE>"
)

var cert *x509.Certificate

func init() {
	block, _ := pem.Decode([]byte(certData))
	if block == nil {
		log.Fatal("failed to decode certData, invalid block")
	}
	var err error
	cert, err = x509.ParseCertificate(block.Bytes)
	if err != nil {
		log.Fatalf("failed to parse certificate: %v", err)
	}
}

type linuxStore struct {
	cert *x509.Certificate
	key  *kms.PrivateKey
}

func openStore() (Store, error) {
	awsCfg, err := awsconfig.LoadDefaultConfig(context.Background())
	if err != nil {
		return nil, err
	}
	awsCfg.Region = "us-west-2"
	key, err := kms.NewPrivateKey(context.Background(), svckms.NewFromConfig(awsCfg), kmsKeyId)
	if err != nil {
		return nil, err
	}
	return &linuxStore{cert: cert, key: key}, nil
}

func (s *linuxStore) Identities() ([]Identity, error) {
	ident := &linuxIdentity{cert: cert, key: s.key}
	return []Identity{ident}, nil
}

func (s *linuxStore) Import(data []byte, password string) error {
	return fmt.Errorf("import not supported")
}

func (s *linuxStore) Close() {}

type linuxIdentity struct {
	cert *x509.Certificate
	key  *kms.PrivateKey
}

func (i *linuxIdentity) Certificate() (*x509.Certificate, error) {
	return i.cert, nil
}

func (i *linuxIdentity) CertificateChain() ([]*x509.Certificate, error) {
	return []*x509.Certificate{i.cert}, nil
}

func (i *linuxIdentity) Signer() (crypto.Signer, error) {
	return i.key, nil
}

func (i *linuxIdentity) Delete() error {
	return nil
}

func (i *linuxIdentity) Close() {}
