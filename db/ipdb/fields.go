/*
 * Copyright (c) 2022 shenjunzheng@gmail.com
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

package ipdb

import (
	"github.com/sjzar/ips/model"
)

// "country_name": "中国",
// "region_name": "浙江",
// "city_name": "",
// "isp_domain": "电信",
// "continent_code": "AP",
// "utc_offset": "UTC+8",
// "latitude": "29.19083",
// "longitude": "120.083656",
// "china_admin_code": "330000",
// "owner_domain": "",
// "timezone": "Asia/Shanghai",
// "idd_code": "86",
// "country_code": "CN",

const (
	FieldCountryName    = "country_name"
	FieldRegionName     = "region_name"
	FieldCityName       = "city_name"
	FieldISPDomain      = "isp_domain"
	FieldContinentCode  = "continent_code"
	FieldUTCOffset      = "utc_offset"
	FieldLatitude       = "latitude"
	FieldLongitude      = "longitude"
	FieldChinaAdminCode = "china_admin_code"
	FieldOwnerDomain    = "owner_domain"
	FieldTimezone       = "timezone"
	FieldIddCode        = "idd_code"
	FieldCountryCode    = "country_code"
	FieldIDC            = "idc"
	FieldBaseStation    = "base_station"
	FieldCountryCode3   = "country_code3"
	FieldEuropeanUnion  = "european_union"
	FieldCurrencyCode   = "currency_code"
	FieldCurrencyName   = "currency_name"
	FieldAnycast        = "anycast"
)

// FullFields 全字段列表
var FullFields = []string{
	FieldCountryName,
	FieldRegionName,
	FieldCityName,
	FieldISPDomain,
	FieldContinentCode,
	FieldUTCOffset,
	FieldLatitude,
	FieldLongitude,
	FieldChinaAdminCode,
	FieldOwnerDomain,
	FieldTimezone,
	FieldIddCode,
	FieldCountryCode,
	FieldIDC,
	FieldBaseStation,
	FieldCountryCode3,
	FieldEuropeanUnion,
	FieldCurrencyCode,
	FieldCurrencyName,
	FieldAnycast,
}

// CommonFieldsMap 公共字段映射
var CommonFieldsMap = map[string]string{
	model.Country:        FieldCountryName,
	model.Province:       FieldRegionName,
	model.City:           FieldCityName,
	model.ISP:            FieldISPDomain,
	model.Continent:      FieldContinentCode,
	model.UTCOffset:      FieldUTCOffset,
	model.Latitude:       FieldLatitude,
	model.Longitude:      FieldLongitude,
	model.ChinaAdminCode: FieldChinaAdminCode,
}

// FieldsFormat 字段格式化，并补充公共字段
func FieldsFormat(data map[string]string) map[string]string {

	// Fill Common Fields
	for k, v := range CommonFieldsMap {
		data[k] = data[v]
	}

	return data
}

// FieldsReplace 字段替换
func FieldsReplace(fields []string) []string {
	ret := make([]string, len(fields))
	copy(ret, fields)

	for i := range ret {
		if v, ok := CommonFieldsMap[ret[i]]; ok {
			ret[i] = v
		}
	}
	return ret
}
