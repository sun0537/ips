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

const (
	// HyperHeaderLength represents the length of the hyper header
	// not including encrypted data and random bytes
	HyperHeaderLength = 12

	// SuperPartLength represents the length of the super part
	// 1 byte DB Type
	// 4 bytes File Size
	// 4 bytes First Index Ptr
	// 4 bytes Total Header Block Size
	// 4 bytes Last Index Ptr
	SuperPartLength = 17

	// HeaderBlockLength represents the length of the header block
	// 16 bytes Start IP
	// 4 bytes Index Ptr
	HeaderBlockLength = 20

	// IPv4 is bitwise representation of the IP version
	IPv4 = 0x0

	// IPv4Length represents the length of an IPv4 address
	IPv4Length = 4

	// IPv4IndexBlockLength represents the length of an IPv4 index block
	// 4 bytes Start IP
	// 4 bytes End IP
	// 4 bytes Data Ptr
	// 1 byte Data Length
	IPv4IndexBlockLength = 13

	// IPv6 is bitwise representation of the IP version
	IPv6 = 0x1

	// IPv6Length represents the length of an IPv6 address
	IPv6Length = 16

	// IPv6IndexBlockLength represents the length of an IPv6 index block
	// 16 bytes Start IP
	// 16 bytes End IP
	// 4 bytes Data Ptr
	// 1 byte Data Length
	IPv6IndexBlockLength = 37

	// FIXME: official database is incomplete, wait for official processing.
	TempDataNotFound = "DataNotFound"
)
