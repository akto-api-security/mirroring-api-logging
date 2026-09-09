package ssl

import (
	"fmt"
	"github.com/akto-api-security/mirroring-api-logging/ebpf/bpfwrapper"
	"log/slog"
	"os/exec"
	"regexp"
	"strconv"
	"strings"

	"github.com/iovisor/gobpf/bcc"
)

var (
	LibCryptoName = "libcrypto.so"
	LibSslName    = "libssl.so"
)

var (
	openSSLVersionRegex = regexp.MustCompile(`^OpenSSL\s+(?P<Major>\d)\.(?P<Minor>\d)\.(?P<Fix>\d+)\w?`)
)

func TryOpensslProbes(m map[string]bool, bpfModule *bcc.Module) (bool, error) {

	var libCryptoPath, libSslPath string
	modules, err := FindModules(m, LibCryptoName, LibSslName)

	if err != nil {
		return false, err
	}

	if len(modules) == 0 {
		return false, fmt.Errorf("no modules found")
	}
	slog.Debug("Modules found", "modules", modules)
	if libCrypto, exist := modules[LibCryptoName]; exist && len(libCrypto) > 0 {
		libCryptoPath = libCrypto
	}
	if libssl, exist := modules[LibSslName]; exist && len(libssl) > 0 {
		libSslPath = libssl
	}
	if len(modules) != 2 {
		return false, fmt.Errorf("the OpenSSL library not complete, libCrypto: %s, libssl: %s", libCryptoPath, libSslPath)
	}

	addresses, err := buildOpenSSLSymAddrConfig(libCryptoPath)
	if err != nil {
		return false, err
	}
	if addresses == nil {
		return false, fmt.Errorf("could not found the symbol address config")
	}

	slog.Debug("Attaching on", "path", libSslPath)
	switch addresses.version {
	case V_1_0:
		if err := bpfwrapper.AttachUprobes(libSslPath, -1, bpfModule, bpfwrapper.SslHooks_1_0); err != nil {
			slog.Error("failed to attach SSL uprobe", "error", err)
		}
		break
	case V_1_1:
		if err := bpfwrapper.AttachUprobes(libSslPath, -1, bpfModule, bpfwrapper.SslHooks_1_1); err != nil {
			slog.Error("failed to attach SSL uprobe", "error", err)
		}
		break
	case V_3_0, V_3_2:
		if err := bpfwrapper.AttachUprobes(libSslPath, -1, bpfModule, bpfwrapper.SslHooks_3_0); err != nil {
			slog.Error("failed to attach SSL 3.x uprobe", "error", err)
		}
		if err := bpfwrapper.AttachUprobes(libSslPath, -1, bpfModule, bpfwrapper.SslHooks_3_0_ex); err != nil {
			slog.Error("failed to attach SSL 3.x ex uprobe", "error", err)
		}
	case V_3_5:
		if err := bpfwrapper.AttachUprobes(libSslPath, -1, bpfModule, bpfwrapper.SslHooks_3_5); err != nil {
			slog.Error("failed to attach SSL 3.5 uprobe", "error", err)
		}
		if err := bpfwrapper.AttachUprobes(libSslPath, -1, bpfModule, bpfwrapper.SslHooks_3_5_ex); err != nil {
			slog.Error("failed to attach SSL 3.5 ex uprobe", "error", err)
		}
	}

	return true, nil
}

type OpenSSLVersion int

const (
	V_1_0 = iota
	V_1_1
	V_3_0
	V_3_2
	V_3_5
)

type OpenSSLSymbolAddresses struct {
	BIOReadOffset  uint32
	BIOWriteOffset uint32
	FDOffset       uint32
	RoleOffset     uint32
	version        OpenSSLVersion
}

// offsetsForVersion returns the struct field offsets for the given OpenSSL version.
// Offsets are verified against OpenSSL source headers and gdb ptype output on live systems.
//
// bio_st.num (FDOffset): file descriptor field in BIO struct
// ssl_st/ssl_connection_st rbio/wbio (BIOReadOffset/BIOWriteOffset): read/write BIO pointers
// ssl_st/ssl_connection_st server (RoleOffset): 1=server, 0=client
//
// In OpenSSL 3.2+, ssl_st was split: connection fields moved to ssl_connection_st
// (embedded ssl_st base = 64 bytes, then version int + padding, then rbio/wbio/server)
// In OpenSSL 3.4+, a user_ssl pointer (8 bytes) was added before version, shifting offsets further.
func offsetsForVersion(major, minor, fix int) (*OpenSSLSymbolAddresses, error) {
	switch {
	case major == 3 && minor >= 4:
		// 3.4.x - 3.5.x: ssl_connection_st with user_ssl pointer before version
		// verified on OpenSSL 3.5.5 with: sudo gdb -batch -ex "add-symbol-file /usr/lib64/libssl.so.3.5.5" -ex "ptype /o struct ssl_connection_st" -ex "quit"
		// https://github.com/openssl/openssl/blob/openssl-3.5/ssl/ssl_local.h
		return &OpenSSLSymbolAddresses{BIOReadOffset: 80, BIOWriteOffset: 88, FDOffset: 56, RoleOffset: 120, version: V_3_5}, nil
	case major == 3 && minor >= 2:
		// 3.2.x - 3.3.x: ssl_connection_st without user_ssl pointer
		// https://github.com/openssl/openssl/blob/openssl-3.2.0/ssl/ssl_local.h
		return &OpenSSLSymbolAddresses{BIOReadOffset: 72, BIOWriteOffset: 80, FDOffset: 56, RoleOffset: 112, version: V_3_2}, nil
	case major == 3:
		// 3.0.x - 3.1.x: ssl_st layout unchanged, fields still in ssl_st directly
		// https://github.com/openssl/openssl/blob/openssl-3.0.7/ssl/ssl_local.h#L1212-L1227
		// https://github.com/openssl/openssl/blob/openssl-3.1.1/ssl/ssl_local.h
		return &OpenSSLSymbolAddresses{BIOReadOffset: 16, BIOWriteOffset: 24, FDOffset: 56, RoleOffset: 56, version: V_3_0}, nil
	case minor == 0 || (minor == 1 && fix == 0):
		// 1.0.x || 1.1.0
		// https://github.com/openssl/openssl/blob/OpenSSL_1_0_0-stable/crypto/bio/bio.h#L297-L306
		// https://github.com/openssl/openssl/blob/OpenSSL_1_0_0-stable/ssl/ssl.h#L1093-L1138
		return &OpenSSLSymbolAddresses{BIOReadOffset: 16, BIOWriteOffset: 24, FDOffset: 40, RoleOffset: 72, version: V_1_0}, nil
	default:
		// 1.1.1
		// https://github.com/openssl/openssl/blob/OpenSSL_1_1_1-stable/crypto/bio/bio_local.h#L115-L125
		// https://github.com/openssl/openssl/blob/OpenSSL_1_1_1-stable/ssl/ssl_local.h#L1068-L1101
		return &OpenSSLSymbolAddresses{BIOReadOffset: 16, BIOWriteOffset: 24, FDOffset: 48, RoleOffset: 56, version: V_1_1}, nil
	}
}

func buildOpenSSLSymAddrConfig(libCryptoPath string) (*OpenSSLSymbolAddresses, error) {
	// using "strings" command to query the symbol in the libCrypto library
	result, err := exec.Command("strings", libCryptoPath).Output()
	if err != nil {
		return nil, err
	}
	for _, p := range strings.Split(string(result), "\n") {
		subMatch := openSSLVersionRegex.FindStringSubmatch(p)
		if len(subMatch) != 4 {
			continue
		}
		major := subMatch[1]
		minor := subMatch[2]
		fix := subMatch[3]

		slog.Debug("found the libCrypto.so version", "major", major, "minor", minor, "fix", fix)
		// must be number, already validate in the regex
		majorVal, _ := strconv.Atoi(major)
		minorVal, _ := strconv.Atoi(minor)
		fixVal, _ := strconv.Atoi(fix)

		// max support version is 3.5.x
		if majorVal > 3 || (majorVal == 3 && minorVal > 5) {
			return nil, fmt.Errorf("the version of the libCrypto is not support: %s.%s.%s", major, minor, fix)
		}

		conf, err := offsetsForVersion(majorVal, minorVal, fixVal)
		if err != nil {
			return nil, err
		}
		slog.Debug("the libCrypto.so library symbol version config", "version", fmt.Sprintf("%s.%s.%s", major, minor, fix), "bio offset", conf.FDOffset)
		return conf, nil
	}
	return nil, fmt.Errorf("could not fount the version of the libCrypto.so")
}
