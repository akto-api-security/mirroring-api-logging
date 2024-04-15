package ssl

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"os/exec"
	"runtime"
	"strings"
	"unsafe"

	"github.com/iovisor/gobpf/bcc"
	"golang.org/x/arch/arm64/arm64asm"
	"golang.org/x/arch/x86/x86asm"

	"github.com/akto-api-security/mirroring-api-logging/ebpf/uprobeBuilder/elf"
	"github.com/akto-api-security/mirroring-api-logging/ebpf/uprobeBuilder/version"
)

func getGoVersion(elfFile *elf.File, versionSymbol *elf.Symbol) (ver *version.Version, err error) {
	defer func() {
		// if cannot getting version from symbol, then trying to get from strings command
		if ver == nil {
			ver, err = getGoVersionByStrings(elfFile.Path)
		}
	}()
	buffer, err := elfFile.ReadSymbolData(".data", versionSymbol.Location, versionSymbol.Size)
	if err != nil {
		return nil, fmt.Errorf("reading go version struct info failure: %v", err)
	}
	var t = goStringInC{}
	buf := bytes.NewReader(buffer)
	err = binary.Read(buf, binary.LittleEndian, &t)
	if err != nil {
		return nil, fmt.Errorf("read the go structure failure: %v", err)
	}
	buffer, err = elfFile.ReadSymbolData(".data", t.Ptr, t.Size)
	if err != nil {
		return nil, fmt.Errorf("read the go version failure: %v", err)
	}

	// parse versions
	if ver, ok, err := gettingGoVersionFromString(string(buffer)); ok {
		return ver, err
	}
	return nil, fmt.Errorf("the go version is failure to identify, version: %s", string(buffer))
}

func getGoVersionByStrings(p string) (*version.Version, error) {
	result, err := exec.Command("strings", p).Output()
	if err != nil {
		return nil, err
	}
	for _, d := range strings.Split(string(result), "\n") {
		if v, ok, err := gettingGoVersionFromString(strings.TrimSpace(d)); ok {
			return v, err
		}
	}

	return nil, fmt.Errorf("go version is not found from strings")
}

func gettingGoVersionFromString(s string) (v *version.Version, success bool, err error) {
	submatch := goVersionRegex.FindStringSubmatch(s)
	if len(submatch) != 3 {
		return nil, false, nil
	}
	v, err = version.Read(submatch[1], submatch[2], "")
	return v, true, err
}

type goStringInC struct {
	Ptr  uint64
	Size uint64
}

type GoTLSArgsLocationType uint32

const (
	GoTLSArgsLocationTypeStack    GoTLSArgsLocationType = 1
	GoTLSArgsLocationTypeRegister GoTLSArgsLocationType = 2
)

type GoSymbolLocation struct {
	Type   GoTLSArgsLocationType
	Offset uint32
}
type GoTLSSymbolAddress struct {
	// net.Conn addresses
	FDSysFDOffset  uint64
	TLSConnOffset  uint64
	GIDOffset      uint64
	TCPConnOffset  uint64
	IsClientOffset uint64

	// write function relate locations
	WriteConnectionLoc GoSymbolLocation
	WriteBufferLoc     GoSymbolLocation
	WriteRet0Loc       GoSymbolLocation
	WriteRet1Loc       GoSymbolLocation

	// write function relate locations
	ReadConnectionLoc GoSymbolLocation
	ReadBufferLoc     GoSymbolLocation
	ReadRet0Loc       GoSymbolLocation
	ReadRet1Loc       GoSymbolLocation
}

func generateGOTLSSymbolOffsets(elfFile *elf.File, v *version.Version) (*GoTLSSymbolAddress, error) {
	reader, err := elfFile.NewDwarfReader(
		goTLSReadSymbol, goTLSWriteSymbol, goTLSGIDStatusSymbol,
		goTLSPollFDSymbol, goTLSConnSymbol, goTLSRuntimeG)
	if err != nil {
		return nil, err
	}

	symbolAddresses := &GoTLSSymbolAddress{}

	readFunction := reader.GetFunction(goTLSReadSymbol)
	if readFunction == nil {
		return nil, fmt.Errorf("could not found the go tls read symbol: %s", goTLSReadSymbol)
	}
	writeFunction := reader.GetFunction(goTLSWriteSymbol)
	if writeFunction == nil {
		return nil, fmt.Errorf("could not found the go tls write symbol: %s", goTLSWriteSymbol)
	}
	gidStatusFunction := reader.GetFunction(goTLSGIDStatusSymbol)
	if gidStatusFunction == nil {
		return nil, fmt.Errorf("could not found the goid status change symbol: %s", goTLSGIDStatusSymbol)
	}

	sym := elfFile.FindSymbol("go.itab.*net.TCPConn,net.Conn")
	/*
		In go version 1.20, the symbols for compiler generated types
		were switched from having a prefix of `go.` to `go:`.
		See the go 1.20 release notes: https://tip.golang.org/doc/go1.20
	*/
	if sym == nil {
		sym = elfFile.FindSymbol("go:itab.*net.TCPConn,net.Conn")
	}
	if sym == nil {
		return nil, fmt.Errorf("could not found the tcp connection symbol: go./go:itab.*net.TCPConn,net.Conn")
	}
	symbolAddresses.TCPConnOffset = sym.Location

	var retValArg0, retValArg1 = "~r1", "~r2"
	if v.Minor >= 18 {
		retValArg0, retValArg1 = "~r0", "~r1"
	}

	// build the symbols
	var assignError error
	// offset
	assignError = assignGoTLSStructureOffset(assignError, reader, goTLSPollFDSymbol, "Sysfd", &symbolAddresses.FDSysFDOffset)
	assignError = assignGoTLSStructureOffset(assignError, reader, goTLSConnSymbol, "conn", &symbolAddresses.TLSConnOffset)
	assignError = assignGoTLSStructureOffset(assignError, reader, goTLSRuntimeG, "goid", &symbolAddresses.GIDOffset)
	assignError = assignGoTLSStructureOffset(assignError, reader, goTLSConnSymbol, "isClient", &symbolAddresses.IsClientOffset)

	// write
	assignError = assignGoTLSArgsLocation(assignError, writeFunction, "c", &symbolAddresses.WriteConnectionLoc)
	assignError = assignGoTLSArgsLocation(assignError, writeFunction, "b", &symbolAddresses.WriteBufferLoc)
	assignError = assignGoTLSArgsLocation(assignError, writeFunction, retValArg0, &symbolAddresses.WriteRet0Loc)
	assignError = assignGoTLSArgsLocation(assignError, writeFunction, retValArg1, &symbolAddresses.WriteRet1Loc)
	// read
	assignError = assignGoTLSArgsLocation(assignError, readFunction, "c", &symbolAddresses.ReadConnectionLoc)
	assignError = assignGoTLSArgsLocation(assignError, readFunction, "b", &symbolAddresses.ReadBufferLoc)
	assignError = assignGoTLSArgsLocation(assignError, readFunction, retValArg0, &symbolAddresses.ReadRet0Loc)
	assignError = assignGoTLSArgsLocation(assignError, readFunction, retValArg1, &symbolAddresses.ReadRet1Loc)

	return symbolAddresses, assignError
}

func assignGoTLSStructureOffset(err error, reader *elf.DwarfReader, structName, fieldName string, dest *uint64) error {
	if err != nil {
		return err
	}
	structure := reader.GetStructure(structName)
	if structure == nil {
		return fmt.Errorf("the structure is not found, name: %s", structName)
	}
	field := structure.GetField(fieldName)
	if field == nil {
		return fmt.Errorf("the field is not found in structure, structure name: %s, field name: %s", structName, fieldName)
	}
	*dest = uint64(field.Offset)
	return nil
}
func assignGoTLSArgsLocation(err error, function *elf.FunctionInfo, argName string, dest *GoSymbolLocation) error {
	if err != nil {
		return err
	}
	var kSPOffset uint32 = 8
	args := function.Args(argName)
	if args == nil {
		return fmt.Errorf("the args is not found, function: %s, args name: %s", function.Name(), argName)
	}
	if args.Location.Type == elf.ArgLocationTypeStack {
		dest.Type = GoTLSArgsLocationTypeStack
		dest.Offset = uint32(args.Location.Offset) + kSPOffset
	} else if args.Location.Type == elf.ArgLocationTypeRegister {
		dest.Type = GoTLSArgsLocationTypeRegister
		dest.Offset = uint32(args.Location.Offset)
	} else {
		return fmt.Errorf("the location type is not support, function: %s, args name: %s, type: %d",
			function.Name(), argName, args.Location.Type)
	}
	return nil
}

func updateBccTableWithSymAddrs(bpfModule *bcc.Module, pid int32, symAddrs *GoTLSSymbolAddress) error {
	const sz = int(unsafe.Sizeof(GoTLSSymbolAddress{}))
	var asByteSlice []byte = (*(*[sz]byte)(unsafe.Pointer(symAddrs)))[:]
	fmt.Printf("byte arr: %v\n", asByteSlice)

	table := getGoSymAddrsTable(bpfModule)
	key := fmt.Sprint(uint32(pid))
	keyByte, _ := table.KeyStrToBytes(key)

	fmt.Printf("key arr: %v %v \n", key, keyByte)

	if err := table.Set(keyByte, asByteSlice); err != nil {
		return fmt.Errorf("table.Set key %v failed: %v", pid, err)
	}
	return nil
}

func findAddressForFunc(symbol string, elfFile *elf.File) ([]uint64, error) {
	// find the symbol
	targetSymbol := elfFile.FindSymbol(symbol)
	if targetSymbol == nil {
		return nil, fmt.Errorf("could not found the symbol")
	}

	// find the symbol real data buffer
	buffer, err := elfFile.ReadSymbolData(".text", targetSymbol.Location, targetSymbol.Size)
	if err != nil {
		return nil, fmt.Errorf("reading symbol data error: %v", err)
	}

	// based on the base addresses and symbol data buffer
	// calculate all RET addresses
	// https://github.com/iovisor/bcc/issues/1320#issuecomment-407927542
	var addresses []uint64
	for i := 0; i < int(targetSymbol.Size); {
		var instLen int
		if runtime.GOARCH == "arm64" {
			inst, err := arm64asm.Decode(buffer[i:])
			if err != nil {
				i += 4
				continue
			}

			if inst.Op == arm64asm.RET {
				addresses = append(addresses, uint64(i))
			}

			instLen = 4
		} else {
			inst, err := x86asm.Decode(buffer[i:], 64)
			if err != nil {
				return nil, fmt.Errorf("error decode the function data: %v", err)
			}

			if inst.Op == x86asm.RET {
				addresses = append(addresses, uint64(i))
			}

			instLen = inst.Len
		}

		i += instLen
	}

	if len(addresses) == 0 {
		return nil, fmt.Errorf("could not found any return addresses")
	}

	return addresses, nil
}
