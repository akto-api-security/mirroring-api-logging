package ssl

import (
	"fmt"
	"log"
	"os/exec"
	"regexp"
	"strconv"
	"strings"

	"github.com/akto-api-security/mirroring-api-logging/ebpf/bpfwrapper"
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
	fmt.Printf("Modules: %v\n", modules)
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

	fmt.Printf("Attaching on: %v\n", libSslPath)
	switch addresses.version {
	case V_1_0:
		if err := bpfwrapper.AttachUprobes(libSslPath, -1, bpfModule, bpfwrapper.SslHooks_1_0); err != nil {
			log.Printf("%s", err.Error())
		}
		break
	case V_1_1:
		if err := bpfwrapper.AttachUprobes(libSslPath, -1, bpfModule, bpfwrapper.SslHooks_1_1); err != nil {
			log.Printf("%s", err.Error())
		}
		break
	case V_3_0:
		if err := bpfwrapper.AttachUprobes(libSslPath, -1, bpfModule, bpfwrapper.SslHooks_3_0); err != nil {
			log.Printf("%s", err.Error())
		}
		if err := bpfwrapper.AttachUprobes(libSslPath, -1, bpfModule, bpfwrapper.SslHooks_3_0_ex); err != nil {
			log.Printf("%s", err.Error())
		}
		break
	}

	return true, nil
}

type OpenSSLVersion int

const (
	V_1_0 = iota
	V_1_1
	V_3_0
)

type OpenSSLSymbolAddresses struct {
	BIOReadOffset  uint32
	BIOWriteOffset uint32
	FDOffset       uint32
	RoleOffset     uint32
	version        OpenSSLVersion
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

		log.Printf("found the libCrypto.so version: %s.%s.%s", major, minor, fix)
		conf := &OpenSSLSymbolAddresses{}

		// must be number, already validate in the regex
		majorVal, _ := strconv.Atoi(major)
		minorVal, _ := strconv.Atoi(minor)
		fixVal, _ := strconv.Atoi(fix)

		// max support version is 3.0.x
		if majorVal > 3 || (majorVal == 3 && minorVal > 0) {
			return nil, fmt.Errorf("the version of the libCrypto is not support: %s.%s.%s", major, minor, fix)
		}

		// bio offset
		// https://github.com/openssl/openssl/blob/OpenSSL_1_0_0-stable/ssl/ssl.h#L1093-L1111
		// https://github.com/openssl/openssl/blob/OpenSSL_1_1_1-stable/ssl/ssl_local.h#L1068-L1083
		// https://github.com/openssl/openssl/blob/openssl-3.0.7/ssl/ssl_local.h#L1212-L1227
		conf.BIOReadOffset = 16
		conf.BIOWriteOffset = 24
		// fd offset
		if majorVal == 3 && minorVal == 0 {
			// 3.0.x
			// https://github.com/openssl/openssl/blob/openssl-3.0.7/crypto/bio/bio_local.h#L115-L128
			// OPENSSL_NO_DEPRECATED_3_0 is not defined by default unless the user pass the specific build option
			conf.FDOffset = 56
			// https://github.com/openssl/openssl/blob/openssl-3.0.7/ssl/ssl_local.h#L1212-L1245
			conf.RoleOffset = 56
			conf.version = V_3_0
		} else if (minorVal == 0) || (minorVal == 1 && fixVal == 0) {
			// 1.0.x || 1.1.0
			// https://github.com/openssl/openssl/blob/OpenSSL_1_0_0-stable/crypto/bio/bio.h#L297-L306
			conf.FDOffset = 40
			// https://github.com/openssl/openssl/blob/OpenSSL_1_0_0-stable/ssl/ssl.h#L1093-L1138
			conf.RoleOffset = 72
			conf.version = V_1_0
		} else {
			// 1.1.1
			// https://github.com/openssl/openssl/blob/OpenSSL_1_1_1-stable/crypto/bio/bio_local.h#L115-L125
			conf.FDOffset = 48
			// https://github.com/openssl/openssl/blob/OpenSSL_1_1_1-stable/ssl/ssl_local.h#L1068-L1101
			conf.RoleOffset = 56
			conf.version = V_1_1
		}
		log.Printf("the libCrypto.so library symbol version config, version: %s.%s.%s, bio offset: %d",
			major, minor, fix, conf.FDOffset)
		return conf, nil
	}
	return nil, fmt.Errorf("could not fount the version of the libCrypto.so")
}
