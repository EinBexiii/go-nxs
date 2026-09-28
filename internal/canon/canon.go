// Package canon encodes the canonical JSON arrays that NXS signs and hashes.
package canon

import (
	"fmt"
	"strconv"
	"strings"
	"unicode/utf8"
)

// Array returns the UTF-8 bytes of the JSON text that ECMAScript JSON.stringify
// produces for an array of the values. Values must be strings or integers.
func Array(values ...any) ([]byte, error) {
	b := &strings.Builder{}
	b.WriteByte('[')
	for i, v := range values {
		if i > 0 {
			b.WriteByte(',')
		}
		switch v := v.(type) {
		case string:
			if err := quote(b, v); err != nil {
				return nil, err
			}
		case int:
			b.WriteString(strconv.Itoa(v))
		case int64:
			b.WriteString(strconv.FormatInt(v, 10))
		case uint64:
			b.WriteString(strconv.FormatUint(v, 10))
		default:
			return nil, fmt.Errorf("canon: unsupported value %T", v)
		}
	}
	b.WriteByte(']')
	return []byte(b.String()), nil
}

// quote writes s as a JSON string. Unlike encoding/json, it does not escape HTML
// characters, U+2028 or U+2029.
func quote(b *strings.Builder, s string) error {
	if !utf8.ValidString(s) {
		return fmt.Errorf("canon: invalid UTF-8 in %q", s)
	}
	b.WriteByte('"')
	for _, r := range s {
		switch r {
		case '"':
			b.WriteString(`\"`)
		case '\\':
			b.WriteString(`\\`)
		case '\b':
			b.WriteString(`\b`)
		case '\f':
			b.WriteString(`\f`)
		case '\n':
			b.WriteString(`\n`)
		case '\r':
			b.WriteString(`\r`)
		case '\t':
			b.WriteString(`\t`)
		default:
			if r < 0x20 {
				fmt.Fprintf(b, `\u%04x`, r)
			} else {
				b.WriteRune(r)
			}
		}
	}
	b.WriteByte('"')
	return nil
}
