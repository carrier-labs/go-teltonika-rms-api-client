package rmsapi

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"

	"github.com/carrier-labs/go-teltonika-rms-api-client/client"
	"github.com/carrier-labs/go-teltonika-rms-api-client/models"
)

// DeviceListParams allows filtering and paginating the devices endpoint.
type DeviceListParams struct {
	CompanyID int
	Limit     int
}

// DeviceService provides access to device-related API endpoints.
type DeviceService struct {
	Client *client.Client
}

// NewDeviceService creates a new DeviceService.
func NewDeviceService(c *client.Client) *DeviceService {
	return &DeviceService{Client: c}
}

// GetDevices fetches all devices from the RMS API, filtered by the given parameters.
func (s *DeviceService) GetDevices(ctx context.Context, params *DeviceListParams) ([]models.Device, error) {
	query := url.Values{}
	if params != nil {
		if params.CompanyID > 0 {
			query.Set("company_id", fmt.Sprintf("%d", params.CompanyID))
		}
		if params.Limit > 0 {
			query.Set("limit", fmt.Sprintf("%d", params.Limit))
		}
	}
	endpoint := "/devices"
	if len(query) > 0 {
		endpoint += "?" + query.Encode()
	}
	respBody, err := s.Client.DoRequest(ctx, "GET", endpoint, nil)
	if err != nil {
		return nil, err
	}
	var result models.APIResponse[[]models.Device]
	if err := json.Unmarshal(respBody, &result); err != nil {
		return nil, fmt.Errorf("failed to decode devices: %w", err)
	}
	if !result.Success {
		return nil, fmt.Errorf("RMS API returned success=false: %+v", result.Meta)
	}
	return result.Data, nil
}
