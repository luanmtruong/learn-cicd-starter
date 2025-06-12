package auth

import (
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestGetAPIKey(t *testing.T) {
	// Test: Valid API key
	headers := http.Header{
		"Authorization": []string{"ApiKey testkey"},
	}
	key, err := GetAPIKey(headers)
	require.NoError(t, err)
	require.NotNil(t, key)
	assert.Equal(t, "testkey", key)

	// Test: No Authorization header
	headers = http.Header{}
	key, err = GetAPIKey(headers)
	require.EqualError(t, err, ErrNoAuthHeaderIncluded.Error())
	assert.Empty(t, key)

	// Test: wrong prefix
	headers = http.Header{
		"Authorization": []string{"Bearer token"},
	}
	key, err = GetAPIKey(headers)
	require.EqualError(t, err, "malformed authorization header")
	assert.Empty(t, key)

	// Test: missing key
	headers = http.Header{
		"Authorization": []string{"ApiKey"},
	}
	key, err = GetAPIKey(headers)
	require.EqualError(t, err, "malformed authorization header")
	assert.Empty(t, key)

	// Test: empty value
	headers = http.Header{
		"Authorization": []string{"-"},
	}
	key, err = GetAPIKey(headers)
	require.NoError(t, err)
	assert.Empty(t, key)
}

