// Package models provides data structures for the RMS API client.
package models

// Device represents a Teltonika RMS device (partial, extend as needed).
type Device struct {
	ID     string `json:"id"`
	Name   string `json:"name"`
	IMEI   string `json:"imei"`
	Serial string `json:"serial"`
	// Add more fields as needed
}
