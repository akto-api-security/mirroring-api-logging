package fastparser

// Zero-alloc JSON encoding helpers used by JSONEncoder. Each kv* helper assumes a
// leading comma before the key.

import (
	"strconv"
	"unicode/utf8"
)

func kv(dst []byte, key string, val []byte) []byte {
	return appendJSONString(appendKey(dst, key), val)
}
func kvStr(dst []byte, key, val string) []byte {
	dst = appendKey(dst, key)
	dst = append(dst, '"')
	dst = appendJSONEscapedStr(dst, val)
	return append(dst, '"')
}
func kvInt(dst []byte, key string, val int64) []byte {
	dst = appendKey(dst, key)
	dst = append(dst, '"')
	dst = strconv.AppendInt(dst, val, 10)
	return append(dst, '"')
}
func kvBool(dst []byte, key string, val bool) []byte {
	dst = appendKey(dst, key)
	if val {
		return append(dst, `"true"`...)
	}
	return append(dst, `"false"`...)
}
func kvStatusCode(dst []byte, code int) []byte {
	dst = append(dst, `,"statusCode":"`...)
	dst = strconv.AppendInt(dst, int64(code), 10)
	return append(dst, '"')
}
func appendKey(dst []byte, key string) []byte {
	dst = append(dst, ',', '"')
	dst = append(dst, key...)
	return append(dst, '"', ':')
}
func appendStatus(dst []byte, code int, reason []byte) []byte {
	dst = append(dst, '"')
	dst = strconv.AppendInt(dst, int64(code), 10)
	if len(reason) > 0 {
		dst = append(dst, ' ')
		dst = appendJSONEscaped(dst, reason)
	}
	return append(dst, '"')
}
// buildHeadersObject writes the headers as a JSON object {"name":"value",...}.
// When lowercaseHost is set, a Host header (any case) is emitted under the key
// "host" to match the legacy payload; all other names keep their wire case.
// The result is meant to be embedded as a JSON string by the caller.
func buildHeadersObject(dst []byte, hs []Header, lowercaseHost bool) []byte {
	dst = append(dst, '{')
	for i := range hs {
		if i > 0 {
			dst = append(dst, ',')
		}
		if lowercaseHost && asciiEqualFold(hs[i].Name, "host") {
			dst = append(dst, `"host"`...)
		} else {
			dst = appendJSONString(dst, hs[i].Name)
		}
		dst = append(dst, ':')
		dst = appendJSONString(dst, hs[i].Value)
	}
	return append(dst, '}')
}
func appendJSONString(dst, s []byte) []byte {
	dst = append(dst, '"')
	dst = appendJSONEscaped(dst, s)
	return append(dst, '"')
}

const hexdigits = "0123456789abcdef"

// appendJSONEscaped escapes ", \, control chars (<0x20), and replaces invalid
// UTF-8 with U+FFFD so the output is always valid JSON. Valid input takes the
// allocation-free fast path.
func appendJSONEscaped(dst, s []byte) []byte {
	start, i := 0, 0
	for i < len(s) {
		c := s[i]
		if c < 0x80 {
			if c >= 0x20 && c != '"' && c != '\\' {
				i++
				continue
			}
			dst = append(dst, s[start:i]...)
			dst = appendEscByte(dst, c)
			i++
			start = i
			continue
		}
		r, size := utf8.DecodeRune(s[i:])
		if r == utf8.RuneError && size == 1 {
			dst = append(dst, s[start:i]...)
			dst = append(dst, '\\', 'u', 'f', 'f', 'f', 'd')
			i++
			start = i
			continue
		}
		i += size
	}
	return append(dst, s[start:]...)
}

func appendJSONEscapedStr(dst []byte, s string) []byte {
	start, i := 0, 0
	for i < len(s) {
		c := s[i]
		if c < 0x80 {
			if c >= 0x20 && c != '"' && c != '\\' {
				i++
				continue
			}
			dst = append(dst, s[start:i]...)
			dst = appendEscByte(dst, c)
			i++
			start = i
			continue
		}
		r, size := utf8.DecodeRuneInString(s[i:])
		if r == utf8.RuneError && size == 1 {
			dst = append(dst, s[start:i]...)
			dst = append(dst, '\\', 'u', 'f', 'f', 'f', 'd')
			i++
			start = i
			continue
		}
		i += size
	}
	return append(dst, s[start:]...)
}

func appendEscByte(dst []byte, c byte) []byte {
	switch c {
	case '"':
		return append(dst, '\\', '"')
	case '\\':
		return append(dst, '\\', '\\')
	case '\n':
		return append(dst, '\\', 'n')
	case '\r':
		return append(dst, '\\', 'r')
	case '\t':
		return append(dst, '\\', 't')
	default:
		return append(dst, '\\', 'u', '0', '0', hexdigits[c>>4], hexdigits[c&0xf])
	}
}
