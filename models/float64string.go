package models

import (
	"encoding/json"
	"fmt"
	"strconv"
)

// Float64String is a custom type to handle float64 values that may be returned as strings or numbers in JSON.
type Float64String float64

func (f *Float64String) UnmarshalJSON(data []byte) error {
	// Remove quotes if present
	var v interface{}
	if err := json.Unmarshal(data, &v); err != nil {
		return err
	}
	switch val := v.(type) {
	case nil:
		*f = 0
		return nil
	case float64:
		*f = Float64String(val)
	case string:
		if val == "" {
			*f = 0
			return nil
		}
		parsed, err := strconv.ParseFloat(val, 64)
		if err != nil {
			return fmt.Errorf("Float64String: cannot parse '%s' as float64: %w", val, err)
		}
		*f = Float64String(parsed)
	default:
		return fmt.Errorf("Float64String: unexpected type %T", v)
	}
	return nil
}

func (f Float64String) Float64() float64 {
	return float64(f)
}
