package tools

import "encoding/json"

// parseJSONLine unmarshals a single JSON line into dest. Returns error on failure.
func parseJSONLine(line string, dest interface{}) error {
	return json.Unmarshal([]byte(line), dest)
}

// parseJSONObj unmarshals a JSON object string into dest.
func parseJSONObj(s string, dest interface{}) error {
	return json.Unmarshal([]byte(s), dest)
}

// parseJSONSlice unmarshals a JSON array string into dest.
func parseJSONSlice(s string, dest interface{}) error {
	return json.Unmarshal([]byte(s), dest)
}
