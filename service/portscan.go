package rmsapi

import (
	"context"
	"encoding/json"
	"fmt"
	"strconv"
	"time"
)

// PortDevice is a single device discovered on one of a router's network ports.
// Vendor is resolved by RMS from the MAC OUI (e.g. "BrightSign").
type PortDevice struct {
	MAC    string `json:"mac"`
	IP     string `json:"ip"`
	Vendor string `json:"vendor"`
}

// portScanTrigger is the synchronous response to triggering a port scan; the
// actual result is delivered asynchronously over the returned status channel.
type portScanTrigger struct {
	Success bool `json:"success"`
	Meta    struct {
		Channel string `json:"channel"`
	} `json:"meta"`
}

// portScanChannelResp is the Status API channel payload once the scan completes.
// data is keyed by device id; each entry carries the scanned ports.
type portScanChannelResp struct {
	Success bool                       `json:"success"`
	Data    map[string][]portScanEntry `json:"data"`
}

type portScanEntry struct {
	Ports     []portScanPort `json:"ports"`
	Status    string         `json:"status"` // "completed" | "warning" | "error" | ...
	Type      string         `json:"type"`   // "port_scan" | "text"
	Value     string         `json:"value"`  // human message on warning/error (e.g. device offline)
	ErrorCode int            `json:"errorcode"`
}

type portScanPort struct {
	ID      int          `json:"id"`
	Type    string       `json:"type"` // "LAN" | "WAN"
	Name    string       `json:"name"`
	Devices []PortDevice `json:"devices"`
}

// ScanLANDevices triggers an ethernet port scan on the given device and returns
// the devices found on its LAN port(s). This is a two-step async flow: the scan
// is triggered on the API host, then its result is polled from the Status API
// channel until the device reports completion.
//
// WAN-side entries (internet hops) are excluded; only LAN-connected devices are
// returned. Note this sees wired devices only — Wi-Fi clients do not appear.
func (s *DeviceService) ScanLANDevices(ctx context.Context, deviceID int) ([]PortDevice, error) {
	// 1) Trigger the scan.
	body, err := s.Client.DoRequest(ctx, "GET", fmt.Sprintf("/devices/%d/port-scan/?type=ethernet", deviceID), nil)
	if err != nil {
		return nil, fmt.Errorf("trigger port scan: %w", err)
	}
	var trig portScanTrigger
	if err := json.Unmarshal(body, &trig); err != nil {
		return nil, fmt.Errorf("decode port scan trigger: %w", err)
	}
	if trig.Meta.Channel == "" {
		return nil, fmt.Errorf("port scan trigger returned no status channel")
	}

	// 2) Poll the Status API channel until the scan completes (~30s cap). The
	// channel 404s ("CHANNEL_NOT_FOUND") for a few seconds while the device
	// responds, so a non-200 is treated as "keep waiting", not an error.
	idKey := strconv.Itoa(deviceID)
	deadline := time.Now().Add(30 * time.Second)
	for {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(1500 * time.Millisecond):
		}

		cb, status, err := s.Client.DoStatusRequest(ctx, "/channel/"+trig.Meta.Channel)
		if err != nil {
			return nil, fmt.Errorf("poll status channel: %w", err)
		}
		if status == 200 {
			var resp portScanChannelResp
			if err := json.Unmarshal(cb, &resp); err == nil {
				for _, entry := range resp.Data[idKey] {
					switch {
					case entry.Status == "completed":
						var out []PortDevice
						for _, p := range entry.Ports {
							if p.Type == "LAN" {
								out = append(out, p.Devices...)
							}
						}
						return out, nil
					case entry.Status == "warning" || entry.Status == "error" || (entry.Type == "text" && entry.Value != ""):
						// Terminal failure reported by the device (e.g. offline);
						// no point polling further.
						msg := entry.Value
						if msg == "" {
							msg = "port scan failed"
						}
						return nil, fmt.Errorf("%s (errorcode %d)", msg, entry.ErrorCode)
					}
				}
			}
		}
		if time.Now().After(deadline) {
			return nil, fmt.Errorf("port scan timed out waiting for device %d", deviceID)
		}
	}
}
