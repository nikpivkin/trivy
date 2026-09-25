package x509

import (
	"testing"

	"github.com/stretchr/testify/require"
)

// TestPrivateKeyObjectSize covers the bound on a private key. Reaching it through Parse
// would take a key of a size that no test can generate in reasonable time.
func TestPrivateKeyObjectSize(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		der     []byte
		wantErr error
	}{
		{
			name:    "within the bound",
			der:     make([]byte, maxPrivateKeyDER),
			wantErr: errMalformedCrypto,
		},
		{
			name:    "over the bound",
			der:     make([]byte, maxPrivateKeyDER+1),
			wantErr: errOversizedKey,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			_, err := parsePEMObject("RSA PRIVATE KEY", tt.der)
			require.ErrorIs(t, err, tt.wantErr)
		})
	}
}
