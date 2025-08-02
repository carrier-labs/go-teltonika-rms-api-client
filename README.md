# Teltonika RMS API Go Client (Skeleton)

This package provides a starting point for interacting with the Teltonika RMS API in Go.

## Features

- API client with authentication placeholder
- Fetch all devices (skeleton)
- Ready for extension

## Authentication

This client supports authentication using a Personal Access Token (PAT) or OAuth2 configuration. To use a PAT, set the `PAT` field in the `client.Config` struct:

```go
import (
	"github.com/carrier-labs/go-teltonika-rms-api-client/client"
	"github.com/carrier-labs/go-teltonika-rms-api-client/service"
)

cfg := client.Config{
	BaseURL: "https://rms.teltonika-networks.com/api", // optional
	PAT:     "<personal_access_token>",
}
c := client.New(cfg)
deviceService := service.NewDeviceService(c)
```

> **Note:** OAuth authentication is not tested in this client. For OAuth2, fill in the `ClientID`, `ClientSecret`, `RedirectURI`, and `Scopes` fields in the config struct. See the RMS API documentation for details.

## Usage Example

```go
package main

import (
	"context"
	"fmt"
	"github.com/carrier-labs/go-teltonika-rms-api-client/client"
	"github.com/carrier-labs/go-teltonika-rms-api-client/service"
)

func main() {
	cfg := client.Config{
		PAT: "<personal_access_token>",
	}
	c := client.New(cfg)
	deviceService := service.NewDeviceService(c)
	devices, err := deviceService.GetDevices(context.Background(), nil)
	if err != nil {
		panic(err)
	}
	for _, d := range devices {
		fmt.Printf("Device: %s (%d)\n", d.Name, d.ID)
	}
}
```

## Notes

- Authentication is a placeholder; see the RMS API docs for the real flow.
- Extend `Device` and response types as needed.
- See https://developers.rms.teltonika-networks.com/ for full API reference.
