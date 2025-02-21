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

package czdb

import (
	"net"
	"strings"

	"github.com/sjzar/ips/format/czdb/sdk"
	"github.com/sjzar/ips/pkg/model"
)

const (
	DBFormat = "czdb"
	DBExt    = ".czdb"
	DBKey    = ""
)

// Reader is a structure that provides functionalities to read from CZDB IP database.
type Reader struct {
	meta   *model.Meta  // Metadata of the IP database
	db     *sdk.Reader  // Database reader instance
	option ReaderOption // Configuration options for the reader.
}

// NewReader initializes a new instance of Reader.
func NewReader(file string) (*Reader, error) {

	db, err := sdk.NewReader(file)
	if err != nil {
		return nil, err
	}

	meta := &model.Meta{
		MetaVersion: model.MetaVersion,
		Format:      DBFormat,
		IPVersion:   model.IPv4,
		Fields:      FullFields,
	}
	meta.AddCommonFieldAlias(CommonFieldsAlias)

	return &Reader{
		meta: meta,
		db:   db,
	}, nil
}

func (r *Reader) Meta() *model.Meta {
	return r.meta
}

func (r *Reader) Find(ip net.IP) (*model.IPInfo, error) {
	ipr, country, err := r.db.Find(ip)
	if err != nil {
		return nil, err
	}

	area := ""
	split := strings.SplitN(country, "\t", 2)
	if len(split) == 2 {
		country, area = split[0], split[1]
	}

	ret := &model.IPInfo{
		IP:     ip,
		IPNet:  ipr,
		Fields: r.meta.Fields,
		Data: map[string]string{
			FieldCountry: country,
			FieldArea:    area,
		},
	}
	ret.AddCommonFieldAlias(CommonFieldsAlias)

	return ret, nil
}

// ReaderOption contains configuration options for the Reader.
type ReaderOption struct {
	Key string
}

// SetOption applies the provided option to the Reader's configuration.
func (r *Reader) SetOption(option interface{}) error {
	if opt, ok := option.(ReaderOption); ok {
		r.db.Key = opt.Key
		r.option = opt
	}

	// FIXME: init database with key
	if r.db.Key != "" {
		if err := r.db.Init(); err == nil {
			if r.db.IsIPv4() {
				r.meta.IPVersion = model.IPv4
			}
			if r.db.IsIPv6() {
				r.meta.IPVersion = model.IPv6
			}
		}
	}
	return nil
}

// Close releases any resources used by the Reader and closes the MMDB database.
func (r *Reader) Close() error {
	return r.db.Close()
}
