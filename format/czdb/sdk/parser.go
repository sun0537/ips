/*
 * Copyright (c) 2025 shenjunzheng@gmail.com
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
	"encoding/base64"
	"encoding/binary"

	"github.com/sjzar/ips/pkg/errors"
)

// validateKey checks if the decryption key is valid and properly formatted.
// Verifies:
// - Key is not empty
// - Key is valid base64 encoded
// Returns:
// - error: ErrKeyRequired if key is empty or decoding error
func (r *Reader) validateKey() error {
	if r.Key == "" {
		return errors.ErrKeyRequired
	}
	_, err := base64.StdEncoding.DecodeString(r.Key)
	return err
}

// decryptHyperHeader decrypts the encrypted hyper header section using AES-ECB.
// Populates:
// - decClientID: decoded client identifier
// - decExpirationDate: database expiration date, format is "YYMMDD" in decimal, e.g. 251216
// - decRandomBytesLength: length of random padding bytes
// Returns:
// - error: decryption failures or invalid header format
func (r *Reader) decryptHyperHeader() error {
	keyBytes, err := base64.StdEncoding.DecodeString(r.Key)
	if err != nil {
		return err
	}
	decryptedData, err := AesECBDecrypt(r.data[HyperHeaderLength:HyperHeaderLength+r.encryptedDataLength], keyBytes)
	if err != nil {
		return err
	}
	r.decClientID = binary.LittleEndian.Uint32(decryptedData[:4]) >> 20
	r.decExpirationDate = binary.LittleEndian.Uint32(decryptedData[:4]) & 0xFFFFF
	r.decRandomBytesLength = int(binary.LittleEndian.Uint32(decryptedData[4:8]))
	r.offset = HyperHeaderLength + r.encryptedDataLength + r.decRandomBytesLength

	return nil
}

// parseSuperPart parses the super block containing database metadata.
// Extracts:
// - dbType: database format version (IPv4/IPv6)
// - fileSize: total database size
// - index pointers: locations of index blocks
// Returns:
// - error: invalid super block format
func (r *Reader) parseSuperPart() error {
	superPartData := r.data[r.offset : r.offset+SuperPartLength]
	r.dbType = uint(superPartData[0])
	r.fileSize = int(binary.LittleEndian.Uint32(superPartData[1:5]))
	r.firstIndexPtr = int(binary.LittleEndian.Uint32(superPartData[5:9]))
	r.totalHeaderBlockSize = int(binary.LittleEndian.Uint32(superPartData[9:13]))
	r.lastIndexPtr = int(binary.LittleEndian.Uint32(superPartData[13:]))
	r.setupIPVersion()
	return nil
}

// parseHeaderBlocks processes the header blocks containing IP range index information.
// Builds:
// - headerIPs: list of starting IP addresses for each header block
// - headerPtrs: corresponding index pointers
// Returns:
// - error: invalid header block format
func (r *Reader) parseHeaderBlocks() error {
	idx := 0
	r.headerIPs = make([][]byte, r.totalHeaderBlockSize/HeaderBlockLength)
	r.headerPtrs = make([]int, r.totalHeaderBlockSize/HeaderBlockLength)
	for i := 0; i < r.totalHeaderBlockSize; i += HeaderBlockLength {
		headerPtr := binary.LittleEndian.Uint32(r.data[r.offset+SuperPartLength+i+16:])
		if headerPtr == 0 {
			break
		}
		r.headerIPs[idx] = r.data[r.offset+SuperPartLength+i : r.offset+SuperPartLength+i+16]
		r.headerPtrs[idx] = int(headerPtr)
		idx++
	}
	r.headerLen = idx
	return nil
}

func (r *Reader) loadGeoSetting() error {
	keyBytes, err := base64.StdEncoding.DecodeString(r.Key)
	if err != nil {
		return err
	}
	r.geo.columnSelection = int(binary.LittleEndian.Uint32(r.data[r.offset+r.lastIndexPtr+r.indexBlockLength : r.offset+r.lastIndexPtr+r.indexBlockLength+4]))
	if r.geo.columnSelection != 0 {
		geoDataLength := int(binary.LittleEndian.Uint32(r.data[r.offset+r.lastIndexPtr+r.indexBlockLength+4 : r.offset+r.lastIndexPtr+r.indexBlockLength+8]))
		r.geo.data = XorDecrypt(r.data[r.offset+r.lastIndexPtr+r.indexBlockLength+8:r.offset+r.lastIndexPtr+r.indexBlockLength+8+geoDataLength], keyBytes)
	}
	return nil
}

// setupIPVersion sets up the IP version.
func (r *Reader) setupIPVersion() {
	if (r.dbType & IPv6) == 0 {
		r.ipLength = IPv4Length
		r.indexBlockLength = IPv4IndexBlockLength
	} else {
		r.ipLength = IPv6Length
		r.indexBlockLength = IPv6IndexBlockLength
	}
}
