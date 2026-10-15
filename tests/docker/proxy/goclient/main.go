// goclient fetches each URL with net/http's default client, which reads
// HTTPS_PROXY, HTTP_PROXY and NO_PROXY, and trusts SSL_CERT_FILE. It
// prints the status and the complete body, or reports an error and exits 1.
package main

import (
	"fmt"
	"io"
	"net/http"
	"os"
)

func fetch(url string) (int, []byte, error) {
	r, err := http.Get(url)
	if err != nil {
		return 0, nil, err
	}
	b, err := io.ReadAll(r.Body)
	r.Body.Close()
	if err != nil {
		return 0, nil, fmt.Errorf("read %s: %w", url, err)
	}
	return r.StatusCode, b, nil
}

func main() {
	failed := false
	for _, u := range os.Args[1:] {
		status, body, err := fetch(u)
		if err != nil {
			fmt.Println("error:", err)
			failed = true
			continue
		}
		fmt.Printf("%d %s", status, body)
	}
	if failed {
		os.Exit(1)
	}
}
