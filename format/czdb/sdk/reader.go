/*
 * Copyright (c) 2024 shenjunzheng@gmail.com
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package sdk

import (
	"bytes"
	"encoding/binary"
	"io"
	"net"
	"os"
	"sync"

	"github.com/sjzar/ips/ipnet"
	"github.com/sjzar/ips/pkg/errors"
)

// Reader implements the CZDB database reader with lazy initialization and concurrent-safe access.
// It handles both IPv4 and IPv6 database formats with AES-ECB encrypted headers.
//
// Usage lifecycle:
//  1. Create instance via NewReader()
//  2. Set decryption Key (base64 encoded)
//  3. Call Find() for IP queries
//  4. Close() when done (implements io.Closer)
type Reader struct {
	// Key contains the base64-encoded decryption key required for database access.
	Key string

	// data holds the complete database file content in memory.
	// detail format see doc.go
	data []byte

	// --- Hyper Header ---
	version             uint32 // format "YYYYMMDD" in decimal, e.g. 20241211
	clientID            uint32 // client identifier
	encryptedDataLength int    // length of encrypted data

	// --- Decrypted Hyper Header ---
	decClientID          uint32 // decrypted client identifier
	decExpirationDate    uint32 // format is "YYMMDD" in decimal, e.g. 251216
	decRandomBytesLength int

	// --- Super Part ---
	dbType               uint // Database type flags (bit0: 0x0=IPv4, 0x1=IPv6)
	fileSize             int
	firstIndexPtr        int
	totalHeaderBlockSize int
	lastIndexPtr         int

	// --- Initialization control ---
	inited   bool // whether the database has been inited
	initOnce sync.Once
	initErr  error

	// offset marks the start position of the Super Part after:
	// HyperHeader(12) + EncryptedData + RandomPadding
	offset int

	// --- Indexing parameters ---
	ipLength         int // IP address length (4 for IPv4, 16 for IPv6)
	indexBlockLength int // Size of each index block (13/37 bytes)

	// geo handles geographical data parsing with column selection
	geo Geo

	// --- Header block cache ---
	headerIPs  [][]byte // Starting IPs of each header block
	headerPtrs []int    // Corresponding index pointers
	headerLen  int      // totalHeaderBlockSize/HeaderBlockLength
}

// NewReader creates a new CZDB database reader from the specified file path.
// It parses the hyper header information but does not decrypt the data immediately.
// Returns:
// - *Reader: initialized reader instance
// - error: possible errors during file reading or header validation
func NewReader(filePath string) (*Reader, error) {
	file, err := os.Open(filePath)
	if err != nil {
		return nil, err
	}
	defer func() {
		_ = file.Close()
	}()

	data, err := io.ReadAll(file)
	if err != nil {
		return nil, err
	}

	if len(data) < HyperHeaderLength {
		return nil, errors.ErrInvalidDatabase
	}

	r := &Reader{
		data:                data,
		version:             binary.LittleEndian.Uint32(data[:4]),
		clientID:            binary.LittleEndian.Uint32(data[4:]),
		encryptedDataLength: int(binary.LittleEndian.Uint32(data[8:])),
	}

	if len(data) < r.encryptedDataLength+HyperHeaderLength {
		return nil, errors.ErrInvalidDatabase
	}

	return r, nil
}

// Init performs full initialization of the database reader including decryption and data parsing.
// This method is called automatically on first Find() call.
// Returns:
// - error: possible errors during decryption or data parsing
func (r *Reader) Init() error {

	if err := r.validateKey(); err != nil {
		return err
	}
	if err := r.decryptHyperHeader(); err != nil {
		return err
	}
	if err := r.parseSuperPart(); err != nil {
		return err
	}
	if err := r.parseHeaderBlocks(); err != nil {
		return err
	}
	if err := r.loadGeoSetting(); err != nil {
		return err
	}
	r.inited = true
	return nil
}

// Find locates geographical information for the given IP address.
// Parameters:
// - ip: net.IP object representing the target IP address
// Returns:
// - *ipnet.Range: IP range containing the target IP
// - string: geographical information in formatted string
// - error: search failures or data parsing errors
//
// Note:
// - Will automatically perform lazy initialization on first call
// - Returned IP range bytes should not be modified
// - Empty string return indicates no geographical data found
func (r *Reader) Find(ip net.IP) (*ipnet.Range, string, error) {
	if !r.inited {
		r.initOnce.Do(func() {
			r.initErr = r.Init()
		})
		if r.initErr != nil {
			return nil, "", r.initErr
		}
	}
	if r.dbType == IPv4 {
		ip = ip.To4()
	} else {
		ip = ip.To16()
	}

	sptr, eptr := r.searchHeader(ip)
	if sptr == 0 {
		// FIXME: official database is incomplete, wait for official processing.
		// missing 0.0.0.0/32 and [::/128] data
		if net.IP.Equal(ip, net.IPv4zero) || net.IP.Equal(ip, net.IPv6zero) {
			return &ipnet.Range{Start: ip, End: ip}, TempDataNotFound, nil
		}
		return nil, "", errors.ErrInvalidDatabase
	}

	sip, eip, dataPtr, dataLen := r.searchIndex(sptr, eptr, ip)
	if dataPtr == 0 {
		// FIXME: IPv6 database skip IPv4 address range
		if r.dbType == IPv6 && net.IP.Equal(ip, net.IPv4zero) {
			return &ipnet.Range{Start: net.IPv4zero.To16(), End: ipnet.LastIPv4.To16()}, TempDataNotFound, nil
		}
		return nil, "", errors.ErrInvalidDatabase
	}

	data, err := r.geo.ParseGeoInfo(r.data[r.offset+dataPtr : r.offset+dataPtr+dataLen])
	if err != nil {
		return nil, "", err
	}

	return &ipnet.Range{
		Start: sip,
		End:   eip,
	}, data, nil
}

// searchHeader performs binary search in header blocks to locate target index range.
// Parameters:
// - ip: target IP address to search for
// Returns:
// - sptr: start pointer of index blocks range
// - eptr: end pointer of index blocks range
func (r *Reader) searchHeader(ip []byte) (int, int) {
	if r.headerLen == 0 {
		return 0, 0
	}

	l, h := 0, r.headerLen-1
	var sptr, eptr int

	for l <= h {
		m := (l + h) >> 1
		cmp := bytes.Compare(ip, r.headerIPs[m])

		if cmp < 0 {
			h = m - 1
		} else if cmp > 0 {
			l = m + 1
		} else {
			if m > 0 {
				sptr = r.headerPtrs[m-1]
			} else {
				sptr = r.headerPtrs[m]
			}
			eptr = r.headerPtrs[m]
			break
		}
	}

	// less than header range
	if l == 0 && h <= 0 {
		return 0, 0
	}

	if l > h {
		if l < r.headerLen {
			sptr = r.headerPtrs[l-1]
			eptr = r.headerPtrs[l]
		} else if h >= 0 && h+1 < r.headerLen {
			sptr = r.headerPtrs[h]
			eptr = r.headerPtrs[h+1]
		} else {
			sptr = r.headerPtrs[r.headerLen-1]
			eptr = sptr + r.indexBlockLength
		}
	}

	return sptr, eptr
}

// searchIndex performs binary search within index blocks to locate exact IP record.
// Parameters:
// - sptr: start pointer of index blocks range
// - eptr: end pointer of index blocks range
// - ip: target IP address
// Returns:
// - sip: start IP of matched range
// - eip: end IP of matched range
// - dataPtr: offset of geographical data
// - dataLen: length of geographical data
func (r *Reader) searchIndex(sptr, eptr int, ip []byte) ([]byte, []byte, int, int) {
	l, h := 0, (eptr-sptr)/r.indexBlockLength

	sip := make([]byte, r.ipLength)
	eip := make([]byte, r.ipLength)
	var dataPtr int
	var dataLen int

	for l <= h {
		m := (l + h) >> 1
		p := sptr + m*r.indexBlockLength

		cmpStart := bytes.Compare(ip, r.data[r.offset+p:r.offset+p+r.ipLength])
		cmpEnd := bytes.Compare(ip, r.data[r.offset+p+r.ipLength:r.offset+p+2*r.ipLength])
		if cmpStart >= 0 && cmpEnd <= 0 {
			copy(sip, r.data[r.offset+p:r.offset+p+r.ipLength])
			copy(eip, r.data[r.offset+p+r.ipLength:r.offset+p+2*r.ipLength])
			dataPtr = int(binary.LittleEndian.Uint32(r.data[r.offset+p+2*r.ipLength:]))
			dataLen = int(r.data[r.offset+p+2*r.ipLength+4])
			break
		} else if cmpStart < 0 {
			h = m - 1
		} else {
			l = m + 1
		}
	}

	return sip, eip, dataPtr, dataLen
}

// IsIPv4 whether support ipv4
func (r *Reader) IsIPv4() bool {
	return r.dbType == IPv4
}

// IsIPv6 whether support ipv6
func (r *Reader) IsIPv6() bool {
	return r.dbType == IPv6
}

func (r *Reader) Close() error {
	r.data = nil
	r.headerIPs = nil
	r.headerPtrs = nil
	r.geo = Geo{}
	r.inited = false
	r.initErr = nil
	r.initOnce = sync.Once{}
	return nil
}
