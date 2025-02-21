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

/* CZDB Format
	+--------------------------------+
	|          Hyper Header          |
	+--------------------------------+
	|           Super Part           |
	+--------------------------------+
	|          Header Block          |
	+--------------------------------+
	|           Data Block           |
	+--------------------------------+
	|          Index Block           |
	+--------------------------------+
	|          Geo Map Block         |
	+--------------------------------+
	|            Copyright           |
	+--------------------------------+

* All multi-byte integers are stored in Little Endian
* All offsets are calculated from the start of Super Part
* String encoding is UTF-8 unless specified otherwise

Hyper Header
	+--------------------------------+--------------------------------+--------------------------------+
	|         Version (4byte)        |       Client ID (4byte)        | Encrypted Data Length (4byte)  |
	+--------------------------------+--------------------------------+--------------------------------+
	|                                     Encrypted Data (n byte)                                      |
	+--------------------------------+--------------------------------+--------------------------------+
	|                                      Random Bytes (n byte)                                       |
	+--------------------------------+--------------------------------+--------------------------------+
* Version format is "YYYYMMDD" in decimal, e.g. 20241211

Encrypted Data
	+--------------------------------+--------------------------------+--------------------------------+
	|       Client ID (3byte)        |    Expiration Date (5byte)     |  Random Bytes Length (4byte)   |
	+--------------------------------+--------------------------------+--------------------------------+
* AES-128 ECB PKCS5 encrypted
* Expiration Date format is "YYMMDD" in decimal, e.g. 251216

Super Part
	+--------------------------------+--------------------------------+
	|        DB Type (1byte)         |       File Size (4byte)        |
	+--------------------------------+--------------------------------+
	|     First Index Ptr (4byte)    | Total Header Block Size (4byte)|
	+--------------------------------+--------------------------------+
	|     Last Index Ptr (4byte)     |
	+--------------------------------+
* DB Type is 0x0 for IPv4, else for IPv6
* File Size is the size starting from Super Part to the end of the file
* First Index Ptr and Last Index Ptr offset from the start of Super Part

Header Block (single element)
	+--------------------------------+--------------------------------+
	|       Start IP (16byte)        |       Index Ptr (4byte)        |
	+--------------------------------+--------------------------------+
* Start IP is IPv4 or IPv6, IPv4 use first 4 bytes, IPv6 use all 16 bytes
* Index Ptr offset from the start of Super Part

Data Block (single element)
	+--------------------------------+--------------------------------+
	|     Geo Data Length (2byte)    |      Geo Data Ptr (6byte)      |
	+--------------------------------+--------------------------------+
	|                       Other Data (n byte)                       |
	+--------------------------------+--------------------------------+
* Data Block is msgpack format
* Geo Data Ptr offset from the start of Super Part
* Other Data is string format

Index Block (single element)
	+--------------------------------+--------------------------------+
	|                   Start IP (4byte or 16byte)                    |
	+--------------------------------+--------------------------------+
	|                    End IP (4byte or 16byte)                     |
	+--------------------------------+--------------------------------+
	|         Data Ptr (4byte)       |      Data Length (1byte)       |
	+--------------------------------+--------------------------------+
* Start IP and End IP is IPv4 or IPv6, IPv4 use 4 bytes, IPv6 use 16 bytes
* Data Ptr offset from the start of Super Part

Geo Map Block
	+--------------------------------+--------------------------------+
	|    Column Selection (4byte)    |    Geo Data Length (4byte)     |
	+--------------------------------+--------------------------------+
	|                        Geo Data (n byte)                        |
	+--------------------------------+--------------------------------+
* Column Selection is a bitwise flag indicating which columns are selected
* if Column Selection is 0, Geo Map not exists
* Geo Data be decrypted by XOR (Vigenère cipher like)
* Geo Data is msgpack format

Copyright
* like "Copyright © 2024 All Rights Reserved. cz88.net 2024/12/04"

*/
