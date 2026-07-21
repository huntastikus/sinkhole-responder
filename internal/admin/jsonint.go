package admin

import (
	"encoding/json"
	"strconv"
)

// jsonInt64 marshals as a JSON string and unmarshals from a JSON string OR
// number, so int64 values larger than JS's 2^53 survive a browser round-trip.
type jsonInt64 int64

func (v jsonInt64) MarshalJSON() ([]byte, error) {
	return json.Marshal(strconv.FormatInt(int64(v), 10))
}

func (v *jsonInt64) UnmarshalJSON(data []byte) error {
	// Accept a quoted string first.
	var s string
	if err := json.Unmarshal(data, &s); err == nil {
		n, perr := strconv.ParseInt(s, 10, 64)
		if perr != nil {
			return perr
		}
		*v = jsonInt64(n)
		return nil
	}
	// Fall back to a bare number (lenient for older/test callers).
	var n int64
	if err := json.Unmarshal(data, &n); err != nil {
		return err
	}
	*v = jsonInt64(n)
	return nil
}
