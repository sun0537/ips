/*
 * Copyright (c) 2023 shenjunzheng@gmail.com
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

package errors

import (
	"errors"
)

var (
	// Format

	ErrUnsupportedIPVersion   = errors.New("unsupported IP version")
	ErrUnsupportedFormat      = errors.New("unsupported format")
	ErrInvalidDatabase        = errors.New("invalid database")
	ErrInvalidFormat          = errors.New("invalid format")
	ErrMismatchedFieldsLength = errors.New("mismatched fields length")
	ErrInvalidCIDR            = errors.New("invalid CIDR format")
	ErrCIDROverlap            = errors.New("CIDR overlap detected")
	ErrMetaMissing            = errors.New("meta information missing")
	ErrNilWriter              = errors.New("writer is not initialized")
	ErrUnsupportedLanguage    = errors.New("unsupported language")
	ErrKeyRequired            = errors.New("key is required for encrypted database, use `--database-option \"key=<your key>\"` or `--input-option \"key=<your key>\"` option to set")

	// IPio

	ErrNoDatabaseReaders = errors.New("no database readers provided")
	ErrInvalidIPRange    = errors.New("invalid IP range")

	// Operate

	ErrFileEmpty           = errors.New("file is empty")
	ErrFieldInvalid        = errors.New("invalid field specified")
	ErrMetaFieldsUndefined = errors.New("no fields defined in meta")

	// Command

	ErrFileNotFound      = errors.New("file not found")
	ErrFailedDownload    = errors.New("failed to download")
	ErrInvalidDirectory  = errors.New("invalid directory path")
	ErrMissingConfigName = errors.New("config name not specified")
	ErrDiscoveryFailed   = errors.New("failed to discover IP address")

	// Server

	ErrInvalidIP = errors.New("invalid IP address")
)
