package security

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/aiseeq/glint/pkg/rules/rulestest"
)

func TestECDSAPublicKeyUncheckedCoordinates(t *testing.T) {
	project := rulestest.Project(t, map[string]string{"key.go": `package keys

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"math/big"
)

func unchecked(curve elliptic.Curve, xBytes, yBytes []byte) *ecdsa.PublicKey {
	x := new(big.Int).SetBytes(xBytes)
	y := new(big.Int).SetBytes(yBytes)
	return &ecdsa.PublicKey{Curve: curve, X: x, Y: y}
}

func checked(curve elliptic.Curve, xBytes, yBytes []byte) *ecdsa.PublicKey {
	x := new(big.Int).SetBytes(xBytes)
	y := new(big.Int).SetBytes(yBytes)
	if !curve.IsOnCurve(x, y) {
		return nil
	}
	return &ecdsa.PublicKey{Curve: curve, X: x, Y: y}
}

func generated(curve elliptic.Curve) *ecdsa.PublicKey {
	x, y := curve.ScalarBaseMult([]byte{1})
	return &ecdsa.PublicKey{Curve: curve, X: x, Y: y}
}

func parsed(curve elliptic.Curve, point []byte) (*ecdsa.PublicKey, error) {
	return ecdsa.ParseUncompressedPublicKey(curve, point)
}
`})
	violations, err := NewECDSAPublicKeyUncheckedCoordinatesRule().AnalyzeGoProject(project)
	require.NoError(t, err)
	require.Len(t, violations, 1)
	require.Equal(t, 12, violations[0].Line)
}
