package rmsapi

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"

	"github.com/carrier-labs/go-teltonika-rms-api-client/client"
	"github.com/carrier-labs/go-teltonika-rms-api-client/models"
)

// DeviceFilter allows filtering the devices endpoint.
type DeviceFilter struct {
	CompanyID string
	// Add more fields as needed for future filters
}

// DeviceListResponse is the response from the devices endpoint.
type DeviceListResponse struct {
	Data []models.Device `json:"data"`
	// Add pagination or meta fields if needed
}

// DeviceService provides access to device-related API endpoints.
type DeviceService struct {
	Client *client.Client
}

// NewDeviceService creates a new DeviceService.
func NewDeviceService(c *client.Client) *DeviceService {
	return &DeviceService{Client: c}
}

// GetDevices fetches all devices from the RMS API, filtered by the given filter.
func (s *DeviceService) GetDevices(ctx context.Context, filter DeviceFilter) ([]models.Device, error) {
	params := url.Values{}
	if filter.CompanyID != "" {
		params.Set("company_id", filter.CompanyID)
	}
	endpoint := "/devices"
	if len(params) > 0 {
		endpoint += "?" + params.Encode()
	}
	respBody, err := s.Client.DoRequest(ctx, "GET", endpoint, nil)
	if err != nil {
		return nil, err
	}
	var result DeviceListResponse
	if err := json.Unmarshal(respBody, &result); err != nil {
		return nil, fmt.Errorf("failed to decode devices: %w", err)
	}
	return result.Data, nil
}
