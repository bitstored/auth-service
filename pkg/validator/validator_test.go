package validator_test

import (
	"github.com/bitstored/auth-service/pkg/validator"
	"github.com/stretchr/testify/require"

	"testing"
)

func TestPassword(t *testing.T) {
	tests := []struct {
		name    string
		pass    string
		isValid bool
	}{
		{
			"TestPassword Empty",
			"",
			false,
		},
		{
			"TestPassword No upper",
			"aaaaaa9.",
			false,
		},
		{
			"TestPassword No lower",
			"9AAAAAAAA.",
			false,
		},
		{
			"TestPassword TooShort",
			"test",
			false,
		},
		{
			"TestPassword TooLong",
			"testtesttesttesttesttesttesttesttesttesttesttesttesttesttesttesttesttesttesttesttesttesttesttesttesttesttesttesttesttesttesttest",
			false,
		},
		{
			"TestPassword NotEnoughtStength",
			"Test123",
			false,
		},
		{
			"TestPassword Valid",
			"tesTTest3!",
			true,
		},
		{
			"TestPassword NoNumber",
			"tesTTest!",
			false,
		},
		{
			"TestPassword No symbol",
			"9AAAAAAAAa",
			false,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t1 *testing.T) {
			isValid, err := validator.Password(tc.pass)
			require.Equal(t, tc.isValid, isValid)
			require.Equal(t, isValid, err.Error() == nil)
		})
	}
}
func TestEmail(t *testing.T) {
	tests := []struct {
		name    string
		email   string
		isValid bool
	}{
		{
			"TestEmail Empty",
			"",
			false,
		},
		{
			"TestEmail Invalid",
			"test@test",
			false,
		},
		{
			"TestEmail Valid",
			"testtest@test.com",
			true,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t1 *testing.T) {
			isValid := validator.Email(tc.email)
			require.Equal(t, tc.isValid, isValid)
		})
	}
}
