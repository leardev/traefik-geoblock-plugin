package traefik_geoblock_plugin

// mmdb.go — Pure-Go minimal MMDB reader. No external dependencies.
// Supports the IPInfo Lite MMDB format (24/28/32-bit record sizes, IPv4 and IPv6).
// The database file is loaded entirely into memory on open.

import (
	"encoding/binary"
	"fmt"
	"net"
	"os"
)

const mmdbMetadataMarker = "\xab\xcd\xefMaxMind.com"

// mmdbReader holds the raw MMDB byte slice and parsed metadata needed for lookups.
type mmdbReader struct {
	data       []byte
	nodeCount  uint32
	recordSize uint32
	ipVersion  uint32
	treeSize   uint32 // nodeCount * recordSize * 2 / 8
	dataOffset uint32 // treeSize + 16 (accounts for 16-byte separator)
}

// openMMDB reads an MMDB file from disk and parses it into memory.
func openMMDB(path string) (*mmdbReader, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("mmdb: read %s: %w", path, err)
	}
	return parseMMDB(data)
}

// parseMMDB parses a raw MMDB byte slice.
func parseMMDB(data []byte) (*mmdbReader, error) {
	// Find the LAST occurrence of the metadata marker.
	idx := -1
	for i := len(data) - len(mmdbMetadataMarker); i >= 0; i-- {
		if string(data[i:i+len(mmdbMetadataMarker)]) == mmdbMetadataMarker {
			idx = i + len(mmdbMetadataMarker)
			break
		}
	}
	if idx < 0 {
		return nil, fmt.Errorf("mmdb: metadata marker not found")
	}

	nc, rs, iv, err := decodeMMDBMetadata(data, uint32(idx))
	if err != nil {
		return nil, err
	}

	treeSize := nc * rs * 2 / 8
	return &mmdbReader{
		data:       data,
		nodeCount:  nc,
		recordSize: rs,
		ipVersion:  iv,
		treeSize:   treeSize,
		dataOffset: treeSize + 16,
	}, nil
}

// lookup implements ipLookup. Returns a 2-letter country code or "".
func (r *mmdbReader) lookup(ip net.IP) string {
	var raw []byte
	if ip4 := ip.To4(); ip4 != nil {
		if r.ipVersion == 6 {
			// IPv4-in-IPv6 database: start after 96 zero bits.
			raw = make([]byte, 16)
			copy(raw[12:], ip4)
		} else {
			raw = ip4
		}
	} else {
		if r.ipVersion == 4 {
			return "" // IPv6 address queried against IPv4-only DB
		}
		raw = ip.To16()
	}

	node := uint32(0)
	for _, b := range raw {
		for i := 7; i >= 0; i-- {
			next := r.readRecord(node, uint32((b>>uint(i))&1))
			if next == r.nodeCount {
				return "" // IP not in database
			}
			if next > r.nodeCount {
				offset := r.dataOffset + (next - r.nodeCount - 16)
				return r.findCountryCode(offset)
			}
			node = next
		}
	}
	return ""
}

// readRecord reads the left (bit=0) or right (bit=1) child of a tree node.
func (r *mmdbReader) readRecord(node, bit uint32) uint32 {
	switch r.recordSize {
	case 24: // 6 bytes per node
		off := node * 6
		if bit == 0 {
			return uint32(r.data[off])<<16 | uint32(r.data[off+1])<<8 | uint32(r.data[off+2])
		}
		return uint32(r.data[off+3])<<16 | uint32(r.data[off+4])<<8 | uint32(r.data[off+5])
	case 28: // 7 bytes per node
		off := node * 7
		mid := r.data[off+3]
		if bit == 0 {
			return uint32(mid&0xf0)<<20 | uint32(r.data[off])<<16 | uint32(r.data[off+1])<<8 | uint32(r.data[off+2])
		}
		return uint32(mid&0x0f)<<24 | uint32(r.data[off+4])<<16 | uint32(r.data[off+5])<<8 | uint32(r.data[off+6])
	case 32: // 8 bytes per node
		off := node * 8
		if bit == 0 {
			return binary.BigEndian.Uint32(r.data[off:])
		}
		return binary.BigEndian.Uint32(r.data[off+4:])
	}
	return r.nodeCount // unknown record size → no data
}

// findCountryCode returns the "country_code" string from the data record at offset.
func (r *mmdbReader) findCountryCode(offset uint32) string {
	if offset >= uint32(len(r.data)) {
		return ""
	}
	return r.findStringInMap(offset, "country_code")
}

// findStringInMap decodes an MMDB map at pos in r.data and returns the string
// value for the given key. Returns "" if not found or on any decode error.
func (r *mmdbReader) findStringInMap(pos uint32, key string) string {
	if pos >= uint32(len(r.data)) {
		return ""
	}
	ctrl := r.data[pos]
	pos++
	typ := ctrl >> 5
	sz := uint32(ctrl & 0x1f)

	if typ == 0 { // extended type
		if pos >= uint32(len(r.data)) {
			return ""
		}
		typ = r.data[pos] + 7
		pos++
	}

	if typ == 1 { // pointer — resolve and recurse
		ptr, _ := r.resolvePointer(ctrl, pos)
		return r.findStringInMap(ptr, key)
	}

	if typ != 7 { // must be a map
		return ""
	}

	sz = r.extendSize(sz, &pos)
	for i := uint32(0); i < sz; i++ {
		k, next := r.decodeStringValue(pos)
		if next == 0 {
			return ""
		}
		pos = next

		if k == key {
			v, _ := r.decodeStringValue(pos)
			return v
		}
		pos = r.skipValue(pos)
		if pos == 0 {
			return ""
		}
	}
	return ""
}

// decodeStringValue decodes an MMDB UTF-8 string (or pointer-to-string) at pos.
// Returns (value, posAfter) or ("", 0) on error.
func (r *mmdbReader) decodeStringValue(pos uint32) (string, uint32) {
	if pos >= uint32(len(r.data)) {
		return "", 0
	}
	ctrl := r.data[pos]
	pos++
	typ := ctrl >> 5
	sz := uint32(ctrl & 0x1f)

	if typ == 0 {
		if pos >= uint32(len(r.data)) {
			return "", 0
		}
		typ = r.data[pos] + 7
		pos++
	}

	if typ == 1 { // pointer
		ptr, _ := r.resolvePointer(ctrl, pos)
		v, _ := r.decodeStringValue(ptr)
		ptrSize := uint32((ctrl>>3)&0x3) + 1
		return v, pos + ptrSize
	}

	if typ != 2 { // must be UTF-8 string
		return "", 0
	}

	sz = r.extendSize(sz, &pos)
	if pos+sz > uint32(len(r.data)) {
		return "", 0
	}
	return string(r.data[pos : pos+sz]), pos + sz
}

// skipValue advances past one MMDB value starting at pos in r.data.
func (r *mmdbReader) skipValue(pos uint32) uint32 {
	if pos >= uint32(len(r.data)) {
		return 0
	}
	ctrl := r.data[pos]
	pos++
	typ := ctrl >> 5
	sz := uint32(ctrl & 0x1f)

	if typ == 1 { // pointer — skip without dereferencing
		return pos + uint32((ctrl>>3)&0x3) + 1
	}
	if typ == 0 { // extended type
		if pos >= uint32(len(r.data)) {
			return 0
		}
		typ = r.data[pos] + 7
		pos++
	}

	sz = r.extendSize(sz, &pos)

	switch typ {
	case 2, 4: // string, bytes
		return pos + sz
	case 3: // double (8 bytes)
		return pos + 8
	case 5, 6, 8, 9, 10: // uint16, uint32, int32, uint64, uint128
		return pos + sz
	case 7: // map (sz = entry count)
		for i := uint32(0); i < sz; i++ {
			pos = r.skipValue(pos)
			if pos == 0 {
				return 0
			}
			pos = r.skipValue(pos)
			if pos == 0 {
				return 0
			}
		}
		return pos
	case 11: // array (sz = element count)
		for i := uint32(0); i < sz; i++ {
			pos = r.skipValue(pos)
			if pos == 0 {
				return 0
			}
		}
		return pos
	}
	return 0
}

// extendSize handles MMDB field size extensions (for sz values 29, 30, 31).
func (r *mmdbReader) extendSize(sz uint32, pos *uint32) uint32 {
	switch sz {
	case 29:
		if *pos < uint32(len(r.data)) {
			sz = 29 + uint32(r.data[*pos])
			*pos++
		}
	case 30:
		if *pos+1 < uint32(len(r.data)) {
			sz = 285 + uint32(r.data[*pos])<<8 | uint32(r.data[*pos+1])
			*pos += 2
		}
	case 31:
		if *pos+2 < uint32(len(r.data)) {
			sz = 65821 + uint32(r.data[*pos])<<16 | uint32(r.data[*pos+1])<<8 | uint32(r.data[*pos+2])
			*pos += 3
		}
	}
	return sz
}

// resolvePointer decodes an MMDB pointer and returns (absOffset, posAfter).
// pos must point to the byte immediately after the ctrl byte.
func (r *mmdbReader) resolvePointer(ctrl byte, pos uint32) (uint32, uint32) {
	size := (ctrl >> 3) & 0x3
	switch size {
	case 0:
		v := uint32(ctrl&0x7)<<8 | uint32(r.data[pos])
		return r.dataOffset + v, pos + 1
	case 1:
		v := uint32(ctrl&0x7)<<16 | uint32(r.data[pos])<<8 | uint32(r.data[pos+1]) + 2048
		return r.dataOffset + v, pos + 2
	case 2:
		v := uint32(ctrl&0x7)<<24 | uint32(r.data[pos])<<16 | uint32(r.data[pos+1])<<8 | uint32(r.data[pos+2]) + 526336
		return r.dataOffset + v, pos + 3
	default: // 3
		v := binary.BigEndian.Uint32(r.data[pos:])
		return r.dataOffset + v, pos + 4
	}
}

// close is a no-op — the MMDB data is held as a plain []byte with no open file descriptor.
func (r *mmdbReader) close() {}

// decodeMMDBMetadata parses the MMDB metadata map at start in data and returns
// node_count, record_size, and ip_version.
func decodeMMDBMetadata(data []byte, start uint32) (nodeCount, recordSize, ipVersion uint32, err error) {
	pos := start
	if pos >= uint32(len(data)) {
		return 0, 0, 0, fmt.Errorf("mmdb: metadata out of bounds")
	}
	ctrl := data[pos]
	pos++
	if ctrl>>5 != 7 {
		return 0, 0, 0, fmt.Errorf("mmdb: metadata is not a map (type=%d)", ctrl>>5)
	}
	count := uint32(ctrl & 0x1f)

	for i := uint32(0); i < count; i++ {
		k, vStart, vtyp, vsz, next, ok := readMetaKV(data, pos)
		if !ok {
			break
		}
		pos = next

		switch vtyp {
		case 5, 6: // uint16 or uint32 — our three target fields are always one of these
			v := readMetaUint(data, pos, vsz)
			pos += vsz
			switch k {
			case "node_count":
				nodeCount = v
			case "record_size":
				recordSize = v
			case "ip_version":
				ipVersion = v
			}
		default:
			// Skip unknown/complex values (strings, maps, arrays, etc.).
			pos = skipMetaValue(data, vStart)
			if pos == 0 {
				return 0, 0, 0, fmt.Errorf("mmdb: failed to skip metadata value for key %q", k)
			}
		}
	}

	if nodeCount == 0 || recordSize == 0 || ipVersion == 0 {
		return 0, 0, 0, fmt.Errorf("mmdb: incomplete metadata: nodeCount=%d recordSize=%d ipVersion=%d", nodeCount, recordSize, ipVersion)
	}
	return nodeCount, recordSize, ipVersion, nil
}

// readMetaKV reads one key-value header from the MMDB metadata map at pos.
// Returns the key string, the offset of the value start, the value type and
// raw size field, the position after the header bytes, and whether parsing
// succeeded. The caller is responsible for consuming the value payload.
func readMetaKV(data []byte, pos uint32) (k string, vStart, vtyp, vsz, next uint32, ok bool) {
	n := uint32(len(data))
	if pos >= n {
		return "", 0, 0, 0, 0, false
	}
	// Key is always a short UTF-8 string in MMDB metadata.
	kctrl := data[pos]
	pos++
	if kctrl>>5 != 2 {
		return "", 0, 0, 0, 0, false
	}
	ksz := uint32(kctrl & 0x1f)
	if pos+ksz > n {
		return "", 0, 0, 0, 0, false
	}
	k = string(data[pos : pos+ksz])
	pos += ksz

	if pos >= n {
		return "", 0, 0, 0, 0, false
	}
	vStart = pos
	vctrl := data[pos]
	pos++
	vtyp = uint32(vctrl >> 5)
	vsz = uint32(vctrl & 0x1f)

	if vtyp == 0 { // extended type
		if pos >= n {
			return "", 0, 0, 0, 0, false
		}
		vtyp = uint32(data[pos]) + 7
		pos++
	}
	return k, vStart, vtyp, vsz, pos, true
}

// readMetaUint reads vsz big-endian bytes from data starting at pos and
// returns them as a uint32.
func readMetaUint(data []byte, pos, vsz uint32) uint32 {
	var v uint32
	for j := uint32(0); j < vsz && pos+j < uint32(len(data)); j++ {
		v = v<<8 | uint32(data[pos+j])
	}
	return v
}

// skipMetaValue advances past one MMDB value in data starting at pos.
// Used for skipping metadata fields we don't need (strings, maps, arrays, etc.).
func skipMetaValue(data []byte, pos uint32) uint32 {
	if pos >= uint32(len(data)) {
		return 0
	}
	ctrl := data[pos]
	pos++
	typ := uint32(ctrl >> 5)
	sz := uint32(ctrl & 0x1f)

	if typ == 1 { // pointer
		return pos + uint32((ctrl>>3)&0x3) + 1
	}
	if typ == 0 { // extended type
		if pos >= uint32(len(data)) {
			return 0
		}
		typ = uint32(data[pos]) + 7
		pos++
	}

	sz, pos = decodeMetaSize(data, sz, pos)

	switch typ {
	case 2, 4: // string, bytes
		return pos + sz
	case 3: // double (8 bytes)
		return pos + 8
	case 5, 6, 8, 9, 10: // uint16, uint32, int32, uint64, uint128
		return pos + sz
	case 7: // map (sz = entry count)
		for i := uint32(0); i < sz; i++ {
			pos = skipMetaValue(data, pos)
			if pos == 0 {
				return 0
			}
			pos = skipMetaValue(data, pos)
			if pos == 0 {
				return 0
			}
		}
		return pos
	case 11: // array (sz = element count)
		for i := uint32(0); i < sz; i++ {
			pos = skipMetaValue(data, pos)
			if pos == 0 {
				return 0
			}
		}
		return pos
	}
	return 0
}

// decodeMetaSize handles MMDB field size extensions for sz values 29, 30, and 31.
// Returns the decoded size and the updated position.
func decodeMetaSize(data []byte, sz, pos uint32) (uint32, uint32) {
	switch sz {
	case 29:
		if pos < uint32(len(data)) {
			sz = 29 + uint32(data[pos])
			pos++
		}
	case 30:
		if pos+1 < uint32(len(data)) {
			sz = 285 + uint32(data[pos])<<8 | uint32(data[pos+1])
			pos += 2
		}
	case 31:
		if pos+2 < uint32(len(data)) {
			sz = 65821 + uint32(data[pos])<<16 | uint32(data[pos+1])<<8 | uint32(data[pos+2])
			pos += 3
		}
	}
	return sz, pos
}
