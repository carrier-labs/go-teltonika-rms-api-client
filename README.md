# Teltonika RMS API Go Client (Skeleton)

This package provides a starting point for interacting with the Teltonika RMS API in Go.

## Features

- API client with authentication placeholder
- Fetch all devices (skeleton)
- Ready for extension

## Usage Example

```go
package main

import (
	"context"
	"fmt"
	"github.com/carrier-labs/go-teltonika-rms-api-client/rmsapi"
)

func main() {
	client := rmsapi.NewClient("https://rms.teltonika-networks.com", "<username>", "<password>")
	devices, err := client.GetDevices(context.Background())
	if err != nil {
		panic(err)
	}
	for _, d := range devices {
		fmt.Printf("Device: %s (%s)\n", d.Name, d.ID)
	}
}
```

## Notes

- Authentication is a placeholder; see the RMS API docs for the real flow.
- Extend `Device` and response types as needed.
- See https://developers.rms.teltonika-networks.com/ for full API reference.
