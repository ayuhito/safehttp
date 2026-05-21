package safehttp_test

import (
	"errors"
	"testing"

	safehttp "github.com/ayuhito/safehttp"
	"github.com/stretchr/testify/require"
)

func TestErrorBehavior(t *testing.T) {
	guard, err := safehttp.NewGuard()
	require.NoError(t, err)

	err = guard.CheckURL(mustURL(t, "https://user:pass@example.com/path?token=secret"))
	require.ErrorIs(t, err, safehttp.ErrBlocked)
	require.ErrorIs(t, err, safehttp.ErrBlockedCredentials)

	block, ok := errors.AsType[*safehttp.BlockError](err)
	require.True(t, ok)
	require.NotNil(t, block)

	require.NotContains(t, block.URL, "user")
	require.NotContains(t, block.URL, "pass")
	require.NotContains(t, block.URL, "token")

	msg := (&safehttp.BlockError{Reason: "blocked", Host: "example.com"}).Error()
	require.Equal(t, "safehttp: blocked", msg)
}
