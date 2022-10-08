package dir

import (
	"errors"
	"io/fs"
	"path/filepath"

	"github.com/opencontainers/go-digest"
)

const (
	// ConfigFile is the name of config file
	ConfigFile = "config.json"

	// LocalCertificateExtension defines the extension of the certificate files
	LocalCertificateExtension = ".crt"

	// LocalKeyExtension defines the extension of the key files
	LocalKeyExtension = ".key"

	// LocalKeysDir is the directory name for local key store
	LocalKeysDir = "localkeys"

	// SignatureExtension defines the extension of the signature files
	SignatureExtension = ".sig"

	// SignatureStoreDirName is the name of the signature store directory
	SignatureStoreDirName = "signatures"

	// SigningKeysFile is the file name of signing key info
	SigningKeysFile = "signingkeys.json"

	// TrustPolicyFile is the file name of trust policy info
	TrustPolicyFile = "trustpolicy.json"

	// TrustStoreDir is the directory name of trust store
	TrustStoreDir = "truststore"
)

// DirLevel defines the directory level.
type DirLevel int

const (
	// UnionLevel is the label to specify the directory to union user and system level,
	// and user level has higher priority than system level.
	// [directory spec]: https://github.com/notaryproject/notation/blob/main/specs/directory.md#category
	UnionLevel DirLevel = iota

	// SystemLevel is the label to specify write directory to system level
	SystemLevel

	// UserLevel is the label to specify write directory to user level
	UserLevel
)

// PathManager contains the union directory file system and methods
// to access paths of notation
type PathManager struct {
	ConfigFS  UnionDirFS
	CacheFS   UnionDirFS
	LibexecFS UnionDirFS
}

func checkError(err error) {
	// if path does not exist, the path can be used to create file
	if err != nil && !errors.Is(err, fs.ErrNotExist) {
		panic(err)
	}
}

// Config returns the path of config.json based on named directory level.
func (p *PathManager) Config(dirLevel DirLevel) string {
	var (
		path string
		err  error
	)

	switch dirLevel {
	case UnionLevel:
		path, err = p.ConfigFS.GetPath(ConfigFile)
		checkError(err)
	case SystemLevel:
		path = filepath.Join(systemConfig, ConfigFile)
	case UserLevel:
		path = filepath.Join(userConfig, ConfigFile)
	}

	return path
}

// LocalKey returns the user level path of the local private key and it's certificate
// in the localkeys directory
func (p *PathManager) Localkey(name string) (keyPath, certPath string) {
	keyPath = filepath.Join(userConfig, LocalKeysDir, name+LocalKeyExtension)
	certPath = filepath.Join(userConfig, LocalKeysDir, name+LocalCertificateExtension)
	return
}

// SigningKeyConfig returns the writable user level path of signingkeys.json files
func (p *PathManager) SigningKeyConfig() string {
	return filepath.Join(userConfig, SigningKeysFile)
}

// TrustPolicy returns the path of trustpolicy.json file based on named directory level.
func (p *PathManager) TrustPolicy(dirLevel DirLevel) string {
	var (
		path string
		err  error
	)

	switch dirLevel {
	case UnionLevel:
		path, err = p.ConfigFS.GetPath(TrustPolicyFile)
		checkError(err)
	case SystemLevel:
		path = filepath.Join(systemConfig, TrustPolicyFile)
	case UserLevel:
		path = filepath.Join(userConfig, TrustPolicyFile)
	}

	return path
}

// X509TrustStore returns the path of x509 trust store certificate
// based on named directory level.
func (p *PathManager) X509TrustStore(dirLevel DirLevel, prefix, namedStore string) string {
	var (
		path string
		err  error
	)

	switch dirLevel {
	case UnionLevel:
		path, err = p.ConfigFS.GetPath(TrustStoreDir, "x509", prefix, namedStore)
		checkError(err)
	case SystemLevel:
		path = filepath.Join(systemConfig, TrustStoreDir, "x509", prefix, namedStore)
	case UserLevel:
		path = filepath.Join(userConfig, TrustStoreDir, "x509", prefix, namedStore)
	}

	return path
}

// CachedSignature returns the cached signature file path
func (p *PathManager) CachedSignature(manifestDigest, signatureDigest digest.Digest) string {
	path, err := p.CacheFS.GetPath(
		SignatureStoreDirName,
		manifestDigest.Algorithm().String(),
		manifestDigest.Encoded(),
		signatureDigest.Algorithm().String(),
		signatureDigest.Encoded()+SignatureExtension,
	)
	checkError(err)
	return path
}

// CachedSignatureRoot returns the cached signature root path
func (p *PathManager) CachedSignatureRoot(manifestDigest digest.Digest) string {
	path, err := p.CacheFS.GetPath(
		SignatureStoreDirName,
		manifestDigest.Algorithm().String(),
		manifestDigest.Encoded(),
	)
	checkError(err)
	return path
}

// CachedSignatureStoreDirPath returns the cached signing keys directory
func (p *PathManager) CachedSignatureStoreDirPath() string {
	path, err := p.CacheFS.GetPath(SignatureStoreDirName)
	checkError(err)
	return path
}
