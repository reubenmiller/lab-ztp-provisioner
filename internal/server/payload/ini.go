package payload

import (
	"fmt"
	"strings"
)

// iniSection writes "[name]\n" plus key/value pairs to sb. Pass pairs as
// alternating key, value strings (so callers don't have to hand-format INI).
// Keys whose value is empty are omitted.
func iniSection(sb *strings.Builder, leadingNewline bool, name string, kv ...string) {
	if leadingNewline && sb.Len() > 0 {
		sb.WriteByte('\n')
	}
	sb.WriteByte('[')
	sb.WriteString(name)
	sb.WriteString("]\n")
	for i := 0; i+1 < len(kv); i += 2 {
		k, v := kv[i], kv[i+1]
		if v == "" {
			continue
		}
		fmt.Fprintf(sb, "%s=%s\n", k, v)
	}
}
