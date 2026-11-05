package conntrack

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/akto-api-security/mirroring-api-logging/ebpf/structs"
	"github.com/iovisor/gobpf/bcc"
	"github.com/akto-api-security/mirroring-api-logging/trafficUtil/utils"
)

var enableConnPrefill = false

func init() {
	utils.InitVar("AKTO_CONN_PREFILL", &enableConnPrefill)
}

// SocketInfo holds parsed socket information from /proc/net/tcp
type SocketInfo struct {
	Inode      uint64
	LocalIP    uint32
	LocalPort  uint16
	RemoteIP   uint32
	RemotePort uint16
}

// FdInfo holds file descriptor information
type FdInfo struct {
	Fd    uint32
	Inode uint64
}

// ConnectionInfo combines FD and socket information for a connection
type ConnectionInfo struct {
	Fd         uint32
	RemoteIP   uint32
	RemotePort uint16
	LocalIP    uint32
	LocalPort  uint16
}

// GenTgidFd generates the map key matching the C function gen_tgid_fd
func GenTgidFd(tgid uint32, fd uint32) uint64 {
	return (uint64(tgid) << 32) | uint64(fd)
}

// SerializeConnInfo serializes ConnInfoT to bytes matching BPF map layout
func SerializeConnInfo(info *structs.ConnInfoT) ([]byte, error) {
	buf := new(bytes.Buffer)
	err := binary.Write(buf, binary.LittleEndian, info)
	if err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// ParseProcNetTcp parses /proc/<pid>/net/tcp and /proc/<pid>/net/tcp6
// Returns a map of inode -> SocketInfo
func ParseProcNetTcp(pid uint32) (map[uint64]*SocketInfo, error) {
	sockets := make(map[uint64]*SocketInfo)

	// Parse both tcp and tcp6
	for _, proto := range []string{"tcp", "tcp6"} {
		path := fmt.Sprintf("/proc/%d/net/%s", pid, proto)
		file, err := os.Open(path)
		if err != nil {
			// Skip if file doesn't exist
			continue
		}
		defer file.Close()

		scanner := bufio.NewScanner(file)
		// Skip header line
		if scanner.Scan() {
			// header skipped
		}

		for scanner.Scan() {
			line := scanner.Text()
			info, err := parseTcpLine(line, proto == "tcp6")
			if err != nil {
				continue
			}
			sockets[info.Inode] = info
		}
	}

	return sockets, nil
}

// parseTcpLine parses a single line from /proc/net/tcp or tcp6
// Format: sl local_address rem_address st tx_queue rx_queue tr tm->when retrnsmt uid timeout inode
func parseTcpLine(line string, isIPv6 bool) (*SocketInfo, error) {
	fields := strings.Fields(line)
	if len(fields) < 10 {
		return nil, fmt.Errorf("invalid line format")
	}

	// Parse local address (field 1)
	localIP, localPort, err := parseAddressPort(fields[1], isIPv6)
	if err != nil {
		return nil, err
	}

	// Parse remote address (field 2)
	remoteIP, remotePort, err := parseAddressPort(fields[2], isIPv6)
	if err != nil {
		return nil, err
	}

	// Parse inode (field 9)
	inode, err := strconv.ParseUint(fields[9], 10, 64)
	if err != nil {
		return nil, err
	}

	return &SocketInfo{
		Inode:      inode,
		LocalIP:    localIP,
		LocalPort:  localPort,
		RemoteIP:   remoteIP,
		RemotePort: remotePort,
	}, nil
}

// parseAddressPort parses "IP:PORT" hex format from /proc/net/tcp
// For IPv6, extracts the last 32 bits (matching C code behavior for IPv4-mapped addresses)
func parseAddressPort(addrPort string, isIPv6 bool) (uint32, uint16, error) {
	parts := strings.Split(addrPort, ":")
	if len(parts) != 2 {
		return 0, 0, fmt.Errorf("invalid address:port format")
	}

	// Parse port (always 16-bit hex)
	port, err := strconv.ParseUint(parts[1], 16, 16)
	if err != nil {
		return 0, 0, err
	}

	// Parse IP
	var ip uint32
	if isIPv6 {
		// IPv6 address is 32 hex chars, take last 8 chars (32 bits)
		// This matches the C code: conn_info.ip = (in_addr.s6_addr32)[3]
		ipHex := parts[0]
		if len(ipHex) >= 8 {
			ip64, err := strconv.ParseUint(ipHex[len(ipHex)-8:], 16, 32)
			if err != nil {
				return 0, 0, err
			}
			ip = uint32(ip64)
		}
	} else {
		// IPv4 address is 8 hex chars, already in little-endian
		ip64, err := strconv.ParseUint(parts[0], 16, 32)
		if err != nil {
			return 0, 0, err
		}
		ip = uint32(ip64)
	}

	return ip, uint16(port), nil
}

// GetSocketFds returns all socket file descriptors for a process
func GetSocketFds(pid uint32) ([]FdInfo, error) {
	fdDir := fmt.Sprintf("/proc/%d/fd", pid)
	entries, err := os.ReadDir(fdDir)
	if err != nil {
		return nil, err
	}

	var fds []FdInfo
	for _, entry := range entries {
		fd, err := strconv.ParseUint(entry.Name(), 10, 32)
		if err != nil {
			continue
		}

		// Read symlink to check if it's a socket
		linkPath := filepath.Join(fdDir, entry.Name())
		target, err := os.Readlink(linkPath)
		if err != nil {
			continue
		}

		// Check if it's a socket: socket:[inode]
		if strings.HasPrefix(target, "socket:[") && strings.HasSuffix(target, "]") {
			inodeStr := target[8 : len(target)-1]
			inode, err := strconv.ParseUint(inodeStr, 10, 64)
			if err != nil {
				continue
			}
			fds = append(fds, FdInfo{
				Fd:    uint32(fd),
				Inode: inode,
			})
		}
	}

	return fds, nil
}

// EnumerateExistingConnections returns all existing TCP connections for a PID
func EnumerateExistingConnections(pid uint32) ([]ConnectionInfo, error) {
	// Get socket info by inode
	sockets, err := ParseProcNetTcp(pid)
	if err != nil {
		return nil, err
	}

	// Get FDs and their inodes
	fds, err := GetSocketFds(pid)
	if err != nil {
		return nil, err
	}

	// Match FDs to sockets
	var connections []ConnectionInfo
	for _, fdInfo := range fds {
		if sockInfo, ok := sockets[fdInfo.Inode]; ok {
			// Skip connections with no remote endpoint (listening sockets)
			if sockInfo.RemoteIP == 0 && sockInfo.RemotePort == 0 {
				continue
			}
			connections = append(connections, ConnectionInfo{
				Fd:         fdInfo.Fd,
				RemoteIP:   sockInfo.RemoteIP,
				RemotePort: sockInfo.RemotePort,
				LocalIP:    sockInfo.LocalIP,
				LocalPort:  sockInfo.LocalPort,
			})
		}
	}
	return connections, nil
}

// PopulateConnInfoWithRotation adds a connection to the BPF maps with rotation logic
func PopulateConnInfoWithRotation(
	connInfoTable, connCounterTable, connInfoMapKeysTable *bcc.Table,
	tgidFd uint64,
	connInfo *structs.ConnInfoT,
	maxMapSize int,
) error {
	// Read current counter value
	counterKey := make([]byte, 4) // int key = 0
	counterBytes, err := connCounterTable.Get(counterKey)
	if err != nil {
		// Counter might not exist yet, start at 0
		counterBytes = make([]byte, 4)
	}

	counter := int32(binary.LittleEndian.Uint32(counterBytes))

	// Reset if near limit
	if counter > int32(maxMapSize-5) {
		counter = 0
	}
	counter++

	// Get old key at this index and delete from conn_info_map
	indexKey := make([]byte, 4)
	binary.LittleEndian.PutUint32(indexKey, uint32(counter))

	oldKeyBytes, err := connInfoMapKeysTable.Get(indexKey)
	if err == nil && len(oldKeyBytes) == 8 {
		// Delete old entry
		connInfoTable.Delete(oldKeyBytes)
	}

	// Write new tgid_fd to keys array
	tgidFdBytes := make([]byte, 8)
	binary.LittleEndian.PutUint64(tgidFdBytes, tgidFd)
	if err := connInfoMapKeysTable.Set(indexKey, tgidFdBytes); err != nil {
		return fmt.Errorf("failed to set conn_info_map_keys: %w", err)
	}

	// Serialize and write conn_info to map
	connInfoBytes, err := SerializeConnInfo(connInfo)
	if err != nil {
		return fmt.Errorf("failed to serialize conn_info: %w", err)
	}
	if err := connInfoTable.Set(tgidFdBytes, connInfoBytes); err != nil {
		return fmt.Errorf("failed to set conn_info_map: %w", err)
	}

	// Update counter
	binary.LittleEndian.PutUint32(counterKey, uint32(counter))
	if err := connCounterTable.Set([]byte{0, 0, 0, 0}, counterKey); err != nil {
		return fmt.Errorf("failed to update conn_counter: %w", err)
	}

	return nil
}

// PopulateExistingConnections enumerates and populates all existing connections for given PIDs
func PopulateExistingConnections(
	pids []uint32,
	connInfoTable, connCounterTable, connInfoMapKeysTable *bcc.Table,
	maxMapSize int,
) {
	var totalConnFound, totalConnPopulated int
	var enumerationFailures, populationFailures int

	// Don't actually prefill in C maps, finding conn is still done
	// to know how many are typically open and therefore data is not captured.
	if !enableConnPrefill {
		slog.Debug("connection prefill disabled", "enableConnPrefill", enableConnPrefill)
	}

	for _, pid := range pids {
		connections, err := EnumerateExistingConnections(pid)
		if err != nil {
			enumerationFailures++
			continue
		}

		totalConnFound += len(connections)

		if !enableConnPrefill {
			continue
		}

		for _, conn := range connections {
			tgidFd := GenTgidFd(pid, conn.Fd)

			connInfo := &structs.ConnInfoT{
				Id:               (uint64(pid) << 32) | uint64(pid),
				Fd:               conn.Fd,
				ConnStartNs:      0, // Unknown for pre-existing connections
				Rport:            conn.RemotePort,
				Raddr:            conn.RemoteIP,
				Laddr:            conn.LocalIP,
				Lport:            conn.LocalPort,
				Ssl:              false,
				ReadEventsCount:  0,
				WriteEventsCount: 0,
				MsgSeq:           0, // First data event will init to 1
				PrevDirection:    0, // Irrelevant when msg_seq=0
			}

			err := PopulateConnInfoWithRotation(
				connInfoTable, connCounterTable, connInfoMapKeysTable,
				tgidFd, connInfo, maxMapSize,
			)
			if err != nil {
				populationFailures++
				continue
			}

			totalConnPopulated++
		}
	}

	slog.Info("completed connection prefill",
		"pids_processed", len(pids),
		"total_connections_found", totalConnFound,
		"total_connections_populated", totalConnPopulated,
		"enumeration_failures", enumerationFailures,
		"population_failures", populationFailures,
	)
}
