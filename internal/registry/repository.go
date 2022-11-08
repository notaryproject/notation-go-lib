package registry

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"

	notation "github.com/notaryproject/notation-go/internal"
	"github.com/opencontainers/go-digest"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
	artifactspec "github.com/oras-project/artifacts-spec/specs-go/v1"
	"oras.land/oras-go/v2"
	"oras.land/oras-go/v2/content"
	"oras.land/oras-go/v2/registry"
	"oras.land/oras-go/v2/registry/remote"
)

const (
	maxBlobSizeLimit     = 32 * 1024 * 1024 // 32 MiB
	maxManifestSizeLimit = 4 * 1024 * 1024  // 4 MiB
)

type RepositoryClient struct {
	remote.Repository
}

type SignatureManifest struct {
	Blob        notation.Descriptor
	Annotations map[string]string
}

// NewRepositoryClient creates a new registry client.
func NewRepositoryClient(client remote.Client, ref registry.Reference, plainHTTP bool) *RepositoryClient {
	return &RepositoryClient{
		Repository: remote.Repository{
			Client:    client,
			Reference: ref,
			PlainHTTP: plainHTTP,
		},
	}
}

// Resolve resolves a reference(tag or digest) to a manifest descriptor
func (c *RepositoryClient) Resolve(ctx context.Context, reference string) (notation.Descriptor, error) {
	desc, err := c.Repository.Resolve(ctx, reference)
	if err != nil {
		return notation.Descriptor{}, err
	}
	return notationDescriptorFromOCI(desc), nil
}

// ListSignatureManifests returns all signature manifests given the manifest digest
func (c *RepositoryClient) ListSignatureManifests(ctx context.Context, manifestDigest digest.Digest) ([]SignatureManifest, error) {
	var signatureManifests []SignatureManifest
	if err := c.Repository.Referrers(ctx, ocispec.Descriptor{
		Digest: manifestDigest,
	}, ArtifactTypeNotation, func(referrers []ocispec.Descriptor) error {
		for _, desc := range referrers {
			if desc.MediaType != artifactspec.MediaTypeArtifactManifest {
				continue
			}
			artifact, err := c.getArtifactManifest(ctx, desc.Digest)
			if err != nil {
				return fmt.Errorf("failed to fetch manifest: %v: %v", desc.Digest, err)
			}
			if len(artifact.Blobs) == 0 {
				continue
			}
			signatureManifests = append(signatureManifests, SignatureManifest{
				Blob:        notationDescriptorFromArtifact(artifact.Blobs[0]),
				Annotations: artifact.Annotations,
			})
		}
		return nil
	}); err != nil {
		return nil, err
	}
	return signatureManifests, nil
}

// GetBlob downloads the content of the specified digest's Blob
func (c *RepositoryClient) GetBlob(ctx context.Context, digest digest.Digest) ([]byte, error) {
	desc, err := c.Repository.Blobs().Resolve(ctx, digest.String())
	if err != nil {
		return nil, err
	}
	if desc.Size > maxBlobSizeLimit {
		return nil, fmt.Errorf("signature blob too large: %d", desc.Size)
	}
	return content.FetchAll(ctx, c.Repository.Blobs(), desc)
}

// PutSignatureManifest creates and uploads an signature artifact linking the manifest and the signature
func (c *RepositoryClient) PutSignatureManifest(ctx context.Context, signature []byte, signatureMediaType string, subjectManifest notation.Descriptor, annotations map[string]string) (notation.Descriptor, SignatureManifest, error) {
	signatureDesc, err := c.uploadSignature(ctx, signature, signatureMediaType)
	if err != nil {
		return notation.Descriptor{}, SignatureManifest{}, err
	}

	manifestDesc, err := c.uploadSignatureManifest(ctx, ociDescriptorFromNotation(subjectManifest), signatureDesc, annotations)
	if err != nil {
		return notation.Descriptor{}, SignatureManifest{}, err
	}

	signatureManifest := SignatureManifest{
		Blob:        notationDescriptorFromOCI(signatureDesc),
		Annotations: annotations,
	}
	return notationDescriptorFromOCI(manifestDesc), signatureManifest, nil
}

func (c *RepositoryClient) getArtifactManifest(ctx context.Context, manifestDigest digest.Digest) (artifactspec.Manifest, error) {
	repo := c.Repository
	repo.ManifestMediaTypes = []string{
		artifactspec.MediaTypeArtifactManifest,
	}
	store := repo.Manifests()
	desc, err := store.Resolve(ctx, manifestDigest.String())
	if err != nil {
		return artifactspec.Manifest{}, err
	}
	if desc.Size > maxManifestSizeLimit {
		return artifactspec.Manifest{}, fmt.Errorf("manifest too large: %d", desc.Size)
	}
	manifestJSON, err := content.FetchAll(ctx, store, desc)
	if err != nil {
		return artifactspec.Manifest{}, err
	}

	var manifest artifactspec.Manifest
	err = json.Unmarshal(manifestJSON, &manifest)
	if err != nil {
		return artifactspec.Manifest{}, err
	}
	return manifest, nil
}

// uploadSignature uploads the signature to the registry
// uploadSignature uploads the signature envelope blob to the registry
func (c *RepositoryClient) uploadSignature(ctx context.Context, blob []byte, mediaType string) (ocispec.Descriptor, error) {
	desc := ocispec.Descriptor{
		MediaType: mediaType,
		Digest:    digest.FromBytes(blob),
		Size:      int64(len(blob)),
	}
	if err := c.Repository.Blobs().Push(ctx, desc, bytes.NewReader(blob)); err != nil {
		return ocispec.Descriptor{}, err
	}
	return desc, nil
}

// uploadSignatureManifest uploads the signature manifest to the registry
// uploadSignatureManifest uploads the signature manifest to the registry
func (c *RepositoryClient) uploadSignatureManifest(ctx context.Context, subject, blobDesc ocispec.Descriptor, annotations map[string]string) (ocispec.Descriptor, error) {
	opts := oras.PackOptions{
		Subject:             &subject,
		ManifestAnnotations: annotations,
	}

	manifestDesc, err := oras.Pack(ctx, c.Repository.Manifests(), ArtifactTypeNotation, []ocispec.Descriptor{blobDesc}, opts)
	if err != nil {
		return ocispec.Descriptor{}, err
	}
	return manifestDesc, nil
}

func notationDescriptorFromArtifact(desc artifactspec.Descriptor) notation.Descriptor {
	return notation.Descriptor{
		MediaType: desc.MediaType,
		Digest:    desc.Digest,
		Size:      desc.Size,
	}
}

func notationDescriptorFromOCI(desc ocispec.Descriptor) notation.Descriptor {
	return notation.Descriptor{
		MediaType: desc.MediaType,
		Digest:    desc.Digest,
		Size:      desc.Size,
	}
}

func ociDescriptorFromNotation(desc notation.Descriptor) ocispec.Descriptor {
	return ocispec.Descriptor{
		MediaType: desc.MediaType,
		Digest:    desc.Digest,
		Size:      desc.Size,
	}
}