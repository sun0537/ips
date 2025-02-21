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
	"bytes"

	"github.com/sjzar/ips/pkg/errors"

	"github.com/vmihailenco/msgpack/v5"
)

// Geo handles the parsing and interpretation of geographical data in MessagePack format.
// It manages column selection and data decoding based on the database configuration.
type Geo struct {
	data            []byte
	columnSelection int
}

// ParseGeoInfo decodes and formats geographical information from binary data.
func (g *Geo) ParseGeoInfo(data []byte) (string, error) {

	decoder := msgpack.NewDecoder(bytes.NewReader(data))
	geoPosMixSize, err := decoder.DecodeInt64()
	if err != nil {
		return "", err
	}

	otherData, err := decoder.DecodeString()
	if err != nil {
		return "", err
	}

	if geoPosMixSize == 0 {
		return otherData, nil
	}

	dataLen := int((geoPosMixSize >> 24) & 0xFF)
	dataPtr := int(geoPosMixSize & 0x00FFFFFF)

	if len(g.data) < dataPtr+dataLen {
		return "", errors.ErrInvalidDatabase
	}

	var info string
	decoder = msgpack.NewDecoder(bytes.NewReader(g.data[dataPtr : dataPtr+dataLen]))
	columnNumber, err := decoder.DecodeArrayLen()
	if err != nil {
		return "", err
	}

	for i := 0; i < columnNumber; i++ {
		value, err := decoder.DecodeString()
		if err != nil {
			return "", err
		}

		// columnSelected
		if (g.columnSelection>>(i+1))&1 == 1 {
			if value == "" {
				value = "null"
			}
			info += value
			info += "\t"
		}
	}

	return info + "\t" + otherData, nil
}
