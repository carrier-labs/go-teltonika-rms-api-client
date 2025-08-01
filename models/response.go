// Package models provides data structures for the RMS API client.
package models

// APIError represents an error returned by the RMS API.
type APIError struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}

// APIResponse is the generic structure for all RMS API responses.
type APIResponse[T any] struct {
	Success bool        `json:"success"`
	Data    T           `json:"data"`
	Meta    interface{} `json:"meta"`
	Errors  []APIError  `json:"errors"`
}
