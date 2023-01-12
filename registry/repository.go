package registry

import (
	"context"
	"encoding/json"
	"fmt"

	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
	"oras.land/oras-go/v2"
	"oras.land/oras-go/v2/content"
	"oras.land/oras-go/v2/registry"
)

const (
	maxBlobSizeLimit     = 32 * 1024 * 1024 // 32 MiB
	maxManifestSizeLimit = 4 * 1024 * 1024  // 4 MiB
)

// repositoryClient implements Repository
type repositoryClient struct {
	registry.Repository
}

// NewRepository returns a new Repository
func NewRepository(repo registry.Repository) Repository {
	return &repositoryClient{
		Repository: repo,
	}
}

// Resolve resolves a reference(tag or digest) to a manifest descriptor
func (c *repositoryClient) Resolve(ctx context.Context, reference string) (ocispec.Descriptor, error) {
	return c.Repository.Manifests().Resolve(ctx, reference)
}

// ListSignatures returns signature manifests filtered by fn given the
// artifact manifest descriptor
func (c *repositoryClient) ListSignatures(ctx context.Context, desc ocispec.Descriptor, fn func(signatureManifests []ocispec.Descriptor) error) error {
	return c.Repository.Referrers(ctx, desc, ArtifactTypeNotation, fn)
}

// FetchSignatureBlob returns signature envelope blob and descriptor given
// signature manifest descriptor
func (c *repositoryClient) FetchSignatureBlob(ctx context.Context, desc ocispec.Descriptor) ([]byte, ocispec.Descriptor, error) {
	signatureBlobs, err := c.getSignatureBlobsDesc(ctx, desc)
	if err != nil {
		return nil, ocispec.Descriptor{}, err
	}
	if len(signatureBlobs) != 1 {
		return nil, ocispec.Descriptor{}, fmt.Errorf("signature manifest requries exactly one signature envelope blob, got %d", len(signatureBlobs))
	}
	sigDesc := signatureBlobs[0]
	if sigDesc.Size > maxBlobSizeLimit {
		return nil, ocispec.Descriptor{}, fmt.Errorf("signature blob too large: %d bytes", sigDesc.Size)
	}
	sigBlob, err := content.FetchAll(ctx, c.Repository.Blobs(), sigDesc)
	if err != nil {
		return nil, ocispec.Descriptor{}, err
	}
	return sigBlob, sigDesc, nil
}

// PushSignature creates and uploads an signature manifest along with its
// linked signature envelope blob. Upon successful, PushSignature returns
// signature envelope blob and manifest descriptors.
func (c *repositoryClient) PushSignature(ctx context.Context, mediaType string, blob []byte, subject ocispec.Descriptor, annotations map[string]string, ociImageManifest bool) (blobDesc, manifestDesc ocispec.Descriptor, err error) {
	blobDesc, err = oras.PushBytes(ctx, c.Repository.Blobs(), mediaType, blob)
	if err != nil {
		return ocispec.Descriptor{}, ocispec.Descriptor{}, err
	}

	manifestDesc, err = c.uploadSignatureManifest(ctx, subject, blobDesc, annotations, ociImageManifest)
	if err != nil {
		return ocispec.Descriptor{}, ocispec.Descriptor{}, err
	}

	return blobDesc, manifestDesc, nil
}

// getSignatureBlobsDesc returns signature blob descriptor from
// signature manifest blobs or layers given signature manifest descriptor
func (c *repositoryClient) getSignatureBlobsDesc(ctx context.Context, sigManifestDesc ocispec.Descriptor) ([]ocispec.Descriptor, error) {
	if sigManifestDesc.Size > maxManifestSizeLimit {
		return nil, fmt.Errorf("signature manifest too large: %d bytes", sigManifestDesc.Size)
	}
	manifestJSON, err := content.FetchAll(ctx, c.Repository.Manifests(), sigManifestDesc)
	if err != nil {
		return nil, err
	}

	if sigManifestDesc.MediaType == ocispec.MediaTypeArtifactManifest {
		var sigManifest ocispec.Artifact
		err = json.Unmarshal(manifestJSON, &sigManifest)
		if err != nil {
			return nil, err
		}
		return sigManifest.Blobs, nil
	} else if sigManifestDesc.MediaType == ocispec.MediaTypeImageManifest {
		var sigManifest ocispec.Manifest
		err = json.Unmarshal(manifestJSON, &sigManifest)
		if err != nil {
			return nil, err
		}
		return sigManifest.Layers, nil
	}

	return nil, fmt.Errorf("sigManifestDesc.MediaType requires %q or %q, got %q", ocispec.MediaTypeArtifactManifest, ocispec.MediaTypeImageManifest, sigManifestDesc.MediaType)
}

// uploadSignatureManifest uploads the signature manifest to the registry
func (c *repositoryClient) uploadSignatureManifest(ctx context.Context, subject, blobDesc ocispec.Descriptor, annotations map[string]string, ociImageManifest bool) (ocispec.Descriptor, error) {
	opts := oras.PackOptions{
		Subject:             &subject,
		ManifestAnnotations: annotations,
	}

	// user wants to use OCI Image Manifest to store signatures
	if ociImageManifest {
		opts.PackImageManifest = true
	}

	return oras.Pack(ctx, c.Repository.Manifests(), ArtifactTypeNotation, []ocispec.Descriptor{blobDesc}, opts)
}
