// goclient fetches each URL with net/http's default client, which reads
// HTTPS_PROXY, HTTP_PROXY and NO_PROXY, and trusts SSL_CERT_FILE. It
// prints the status and the body.
package main

import (
	"fmt"
	"io"
	"net/http"
	"os"
)

func main() {
	failed := false
	for _, u := range os.Args[1:] {
		r, err := http.Get(u)
		if err != nil {
			fmt.Println("error:", err)
			failed = true
			continue
		}
		b, _ := io.ReadAll(r.Body)
		r.Body.Close()
		fmt.Printf("%d %s", r.StatusCode, b)
	}
	if failed {
		os.Exit(1)
	}
}
