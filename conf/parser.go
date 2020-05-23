/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2019 ZtSDP LLC. All Rights Reserved.
 */

package conf

import (
	"encoding/base64"
	"fmt"
)

type ParseError struct {
	why      string
	offender string
}

func (e *ParseError) Error() string {
	return fmt.Sprintf("%s: %q", e.why, e.offender)
}

func parseKeyBase64(s string) (*Key, error) {
	k, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		return nil, &ParseError{"Invalid key: " + err.Error(), s}
	}
	if len(k) != KeyLength {
		return nil, &ParseError{"Keys must decode to exactly 32 bytes", s}
	}
	var key Key
	copy(key[:], k)
	return &key, nil
}
