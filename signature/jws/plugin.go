package jws

import (
	"context"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"fmt"

	"github.com/golang-jwt/jwt/v4"
	"github.com/notaryproject/notation-go"
	"github.com/notaryproject/notation-go/spec/plugin"
	"github.com/notaryproject/notation-go/spec/signature"
)

// PluginSigner signs artifacts and generates JWS signatures
// by delegating the one or both operations to the named plugin,
// as defined in
// https://github.com/notaryproject/notaryproject/blob/main/specs/plugin-extensibility.md#signing-interfaces.
type PluginSigner struct {
	Runner       plugin.Runner
	KeyID        string
	PluginConfig map[string]string
}

// Sign signs the artifact described by its descriptor, and returns the signature.
func (s *PluginSigner) Sign(ctx context.Context, desc signature.Descriptor, opts notation.SignOptions) ([]byte, error) {
	out, err := s.Runner.Run(ctx, plugin.CommandGetMetadata, nil)
	if err != nil {
		return nil, fmt.Errorf("metadata command failed: %w", err)
	}
	metadata, ok := out.(*plugin.Metadata)
	if !ok {
		return nil, fmt.Errorf("plugin runner returned incorrect get-plugin-metadata response type '%T'", out)
	}
	if err := metadata.Validate(); err != nil {
		return nil, fmt.Errorf("invalid plugin metadata: %w", err)
	}
	if metadata.HasCapability(plugin.CapabilitySignatureGenerator) {
		return s.generateSignature(ctx, desc, opts)
	} else if metadata.HasCapability(plugin.CapabilityEnvelopeGenerator) {
		return s.generateSignatureEnvelope(ctx, desc, opts)
	}
	return nil, fmt.Errorf("plugin does not have signing capabilities")
}

func (s *PluginSigner) describeKey(ctx context.Context, config map[string]string) (*plugin.DescribeKeyResponse, error) {
	req := &plugin.DescribeKeyRequest{
		ContractVersion: "1",
		KeyID:           s.KeyID,
		PluginConfig:    config,
	}
	out, err := s.Runner.Run(ctx, plugin.CommandDescribeKey, req)
	if err != nil {
		return nil, fmt.Errorf("describe-key command failed: %w", err)
	}
	resp, ok := out.(*plugin.DescribeKeyResponse)
	if !ok {
		return nil, fmt.Errorf("plugin runner returned incorrect describe-key response type '%T'", out)
	}
	return resp, nil
}

func (s *PluginSigner) generateSignature(ctx context.Context, desc signature.Descriptor, opts notation.SignOptions) ([]byte, error) {
	config := s.mergeConfig(opts.PluginConfig)
	// Get key info.
	key, err := s.describeKey(ctx, config)
	if err != nil {
		return nil, err
	}

	// Check keyID is honored.
	if s.KeyID != key.KeyID {
		return nil, fmt.Errorf("keyID mismatch")
	}

	// Get algorithm associated to key.
	alg := key.KeySpec.SignatureAlgorithm()
	if alg == "" {
		return nil, fmt.Errorf("keySpec %q not supported: ", key.KeySpec)
	}

	// Generate payload to be signed.
	payload := packPayload(desc, opts)
	if err := payload.Valid(); err != nil {
		return nil, err
	}

	// Generate signing string.
	token := jwtToken(alg.JWS(), payload)
	signing, err := token.SigningString()
	if err != nil {
		return nil, fmt.Errorf("failed to marshal signing payload: %v", err)
	}

	// Execute plugin sign command.
	req := &plugin.GenerateSignatureRequest{
		ContractVersion: "1",
		KeyID:           s.KeyID,
		KeySpec:         key.KeySpec,
		Hash:            alg.Hash(),
		Payload:         signing,
		PluginConfig:    config,
	}
	out, err := s.Runner.Run(ctx, plugin.CommandGenerateSignature, req)
	if err != nil {
		return nil, fmt.Errorf("generate-signature command failed: %w", err)
	}
	resp, ok := out.(*plugin.GenerateSignatureResponse)
	if !ok {
		return nil, fmt.Errorf("plugin runner returned incorrect generate-signature response type '%T'", out)
	}

	// Check keyID is honored.
	if s.KeyID != resp.KeyID {
		return nil, fmt.Errorf("keyID mismatch")
	}

	// Check algorithm is supported.
	jwsAlg := resp.SigningAlgorithm.JWS()
	if jwsAlg == "" {
		return nil, fmt.Errorf("signing algorithm %q not supported", resp.SigningAlgorithm)
	}

	// Check certificate chain is not empty.
	if len(resp.CertificateChain) == 0 {
		return nil, errors.New("empty certificate chain")
	}

	certs, err := parseCertChain(resp.CertificateChain)
	if err != nil {
		return nil, err
	}

	// Verify the hash of the request payload against the response signature
	// using the public key of the signing certificate.
	signed64Url := base64.RawURLEncoding.EncodeToString(resp.Signature)
	err = verifyJWT(jwsAlg, signing, signed64Url, certs[0])
	if err != nil {
		return nil, fmt.Errorf("verification error: %v", err)
	}

	// Check the the certificate chain conforms to the spec.
	if err := verifyCertExtKeyUsage(certs[0], x509.ExtKeyUsageCodeSigning); err != nil {
		return nil, fmt.Errorf("signing certificate does not meet the minimum requirements: %w", err)
	}

	// Assemble the JWS signature envelope.
	return jwtEnvelope(ctx, opts, signing+"."+signed64Url, resp.CertificateChain)
}

func (s *PluginSigner) mergeConfig(config map[string]string) map[string]string {
	c := make(map[string]string, len(s.PluginConfig)+len(config))
	// First clone s.PluginConfig.
	for k, v := range s.PluginConfig {
		c[k] = v
	}
	// Then set or override entries from config.
	for k, v := range config {
		c[k] = v
	}
	return c
}

func (s *PluginSigner) generateSignatureEnvelope(ctx context.Context, desc signature.Descriptor, opts notation.SignOptions) ([]byte, error) {
	return nil, errors.New("not implemented")
}

func parseCertChain(certChain [][]byte) ([]*x509.Certificate, error) {
	certs := make([]*x509.Certificate, len(certChain))
	for i, cert := range certChain {
		cert, err := x509.ParseCertificate(cert)
		if err != nil {
			return nil, err
		}
		certs[i] = cert
	}
	return certs, nil
}

func verifyJWT(sigAlg string, payload string, sig string, signingCert *x509.Certificate) error {
	// Verify the hash of req.payload against resp.signature using the public key if the leaf certificate.
	method := jwt.GetSigningMethod(sigAlg)
	return method.Verify(payload, sig, signingCert.PublicKey)
}
