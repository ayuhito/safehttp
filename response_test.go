package safehttp_test

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	safehttp "github.com/ayuhito/safehttp"
	"github.com/stretchr/testify/require"
)

func TestResponseBodyLimit(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		switch req.URL.Path {
		case "/exact":
			_, err := io.WriteString(w, "abc")
			if err != nil {
				panic(err)
			}
		case "/large":
			_, err := io.WriteString(w, "abcd")
			if err != nil {
				panic(err)
			}
		default:
			http.NotFound(w, req)
		}
	}))
	t.Cleanup(server.Close)

	client, err := safehttp.NewClient(localServerOptions(t, server.URL, safehttp.MaxResponseBytes(3))...)
	require.NoError(t, err)

	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, server.URL+"/exact", nil)
	require.NoError(t, err)

	resp, err := client.Do(req)
	require.NoError(t, err)

	body, err := io.ReadAll(resp.Body)
	require.NoError(t, resp.Body.Close())
	require.NoError(t, err)
	require.Equal(t, "abc", string(body))

	req, err = http.NewRequestWithContext(context.Background(), http.MethodGet, server.URL+"/large", nil)
	require.NoError(t, err)

	resp, err = client.Do(req)
	require.NoError(t, err)

	body, err = io.ReadAll(resp.Body)
	require.NoError(t, resp.Body.Close())
	require.Equal(t, "abc", string(body))

	maxBytesErr, ok := errors.AsType[*http.MaxBytesError](err)
	require.True(t, ok)
	require.Equal(t, int64(3), maxBytesErr.Limit)
}
