package models

import (
	"database/sql/driver"
	"encoding/json"
	"fmt"
	"strings"
)

// JSONB and StringArray are custom PostgreSQL column types used across all models.

type JSONB map[string]interface{}
type StringArray []string

func (j JSONB) Value() (driver.Value, error) {
	if j == nil {
		return "{}", nil
	}
	b, err := json.Marshal(j)
	return string(b), err
}

func (j *JSONB) Scan(src any) error {
	if src == nil {
		*j = JSONB{}
		return nil
	}
	var s string
	switch v := src.(type) {
	case string:
		s = v
	case []byte:
		s = string(v)
	default:
		return fmt.Errorf("JSONB.Scan: unsupported type %T", src)
	}
	return json.Unmarshal([]byte(s), j)
}

func (a StringArray) Value() (driver.Value, error) {
	if len(a) == 0 {
		return "{}", nil
	}
	quoted := make([]string, len(a))
	for i, s := range a {
		s = strings.ReplaceAll(s, `\`, `\\`)
		s = strings.ReplaceAll(s, `"`, `\"`)
		quoted[i] = `"` + s + `"`
	}
	return "{" + strings.Join(quoted, ",") + "}", nil
}

func (a *StringArray) Scan(src any) error {
	if src == nil {
		*a = StringArray{}
		return nil
	}
	var s string
	switch v := src.(type) {
	case string:
		s = v
	case []byte:
		s = string(v)
	default:
		return fmt.Errorf("StringArray.Scan: unsupported type %T", src)
	}
	s = strings.TrimPrefix(s, "{")
	s = strings.TrimSuffix(s, "}")
	if s == "" {
		*a = StringArray{}
		return nil
	}
	*a = parsePostgresArray(s)
	return nil
}

func parsePostgresArray(s string) []string {
	var result []string
	var cur strings.Builder
	inQuote := false
	escape := false
	for _, r := range s {
		switch {
		case escape:
			cur.WriteRune(r)
			escape = false
		case r == '\\':
			escape = true
		case r == '"':
			inQuote = !inQuote
		case r == ',' && !inQuote:
			result = append(result, cur.String())
			cur.Reset()
		default:
			cur.WriteRune(r)
		}
	}
	if cur.Len() > 0 {
		result = append(result, cur.String())
	}
	return result
}
