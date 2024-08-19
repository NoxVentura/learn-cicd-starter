package auth

import (
	"errors"
	"net/http"
	"reflect"
	"testing"
)

func TestGetAPIKey(t *testing.T) {
	tests := map[string]struct {
		input     http.Header
		want      string
		expectErr error
	}{
		"valid header": {
			input:     http.Header{"Authorization": {"ApiKey 1824792873598127310924568934756985256"}},
			want:      "1824792873598127310924568934756985256",
			expectErr: nil,
		},
		"missing authorization header": {
			input:     http.Header{},
			want:      "",
			expectErr: ErrNoAuthHeaderIncluded,
		},
		"malformed authorization header (missing ApiKey)": {
			input:     http.Header{"Authorization": {"Bearer 1824792873598127310924568934756985256"}},
			want:      "",
			expectErr: errors.New("malformed authorization header"),
		},
		"malformed authorization header (missing key)": {
			input:     http.Header{"Authorization": {"ApiKey"}},
			want:      "",
			expectErr: errors.New("malformed authorization header"),
		},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			got, err := GetAPIKey(tc.input)
			if err != nil {
				_ = err
			}
			if !reflect.DeepEqual(tc.want, got) {
				t.Fatalf("%s: expected key: %v, got: %v, expected error: %v, got: %v", name, tc.want, got, tc.expectErr, err)
			}
		})
	}
}
