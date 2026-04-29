package profiles

import (
	"reflect"
	"strings"
)

// RedactedSentinel is the value substituted for any field tagged
// `ztp:"sensitive"` when a profile is rendered for the API. We use a fixed,
// distinctive marker so UIs can detect the redaction (e.g. show a "Set new
// value" affordance instead of pretending the field is empty).
const RedactedSentinel = "<redacted>"

// Redact returns a deep copy of v with every field tagged `ztp:"sensitive"`
// replaced by RedactedSentinel (for strings) or zero (for non-strings).
// Maps and slices are walked recursively. Pointers are followed; nil
// pointers stay nil.
//
// Redact is conservative: when a struct field carries `ztp:"contains_secrets"`
// the function recurses into it but does not redact the field itself. This
// lets the WiFi struct (a list of WiFiConfig) be marked so its leaf
// `password` field is found, without redacting the whole list.
//
// The function never panics on unexported fields — they are skipped — and
// never mutates the input.
func Redact(v any) any {
	if v == nil {
		return nil
	}
	rv := reflect.ValueOf(v)
	out := redactValue(rv)
	if !out.IsValid() {
		return nil
	}
	return out.Interface()
}

func redactValue(v reflect.Value) reflect.Value {
	if !v.IsValid() {
		return v
	}
	switch v.Kind() {
	case reflect.Pointer:
		if v.IsNil() {
			return v
		}
		inner := redactValue(v.Elem())
		if !inner.IsValid() {
			return v
		}
		out := reflect.New(v.Elem().Type())
		out.Elem().Set(inner)
		return out
	case reflect.Interface:
		if v.IsNil() {
			return v
		}
		return redactValue(v.Elem())
	case reflect.Struct:
		out := reflect.New(v.Type()).Elem()
		out.Set(v)
		t := v.Type()
		for i := 0; i < t.NumField(); i++ {
			f := t.Field(i)
			if !f.IsExported() {
				continue
			}
			tag := f.Tag.Get("ztp")
			tags := strings.Split(tag, ",")
			isSensitive := false
			for _, tok := range tags {
				if strings.TrimSpace(tok) == "sensitive" {
					isSensitive = true
					break
				}
			}
			fv := out.Field(i)
			if isSensitive {
				zeroOrSentinel(fv)
				continue
			}
			fv.Set(redactValue(fv))
		}
		return out
	case reflect.Slice:
		if v.IsNil() {
			return v
		}
		out := reflect.MakeSlice(v.Type(), v.Len(), v.Len())
		for i := 0; i < v.Len(); i++ {
			out.Index(i).Set(redactValue(v.Index(i)))
		}
		return out
	case reflect.Map:
		if v.IsNil() {
			return v
		}
		out := reflect.MakeMapWithSize(v.Type(), v.Len())
		iter := v.MapRange()
		for iter.Next() {
			out.SetMapIndex(iter.Key(), redactValue(iter.Value()))
		}
		return out
	default:
		return v
	}
}

// zeroOrSentinel sets v to its sensitive-field redaction value: the
// RedactedSentinel string for non-empty string fields, the zero value
// otherwise. Empty strings remain empty so the UI can tell "operator hasn't
// configured this" apart from "operator configured a value the API hides".
func zeroOrSentinel(v reflect.Value) {
	if !v.CanSet() {
		return
	}
	switch v.Kind() {
	case reflect.String:
		if v.String() != "" {
			v.SetString(RedactedSentinel)
		}
	case reflect.Slice:
		if v.Len() > 0 && v.Type().Elem().Kind() == reflect.Uint8 {
			v.SetBytes([]byte(RedactedSentinel))
			return
		}
		v.Set(reflect.Zero(v.Type()))
	default:
		v.Set(reflect.Zero(v.Type()))
	}
}
