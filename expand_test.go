package main

import (
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestExpandWithDefault(t *testing.T) {
	t.Setenv("SET_VAR", "hello")
	t.Setenv("EMPTY_VAR", "")
	_ = os.Unsetenv("UNSET_VAR")

	tests := []struct {
		name     string
		template string
		want     string
	}{
		{"plain dollar brace — var set", "${SET_VAR}", "hello"},
		{"plain dollar no brace — var set", "$SET_VAR", "hello"},
		{"colon-dash — var set, default ignored", "${SET_VAR:-fallback}", "hello"},
		{"colon-dash — var unset, returns default", "${UNSET_VAR:-fallback}", "fallback"},
		{"colon-dash — var empty, returns default", "${EMPTY_VAR:-fallback}", "fallback"},
		{"colon-dash — default contains colon (e.g. URL)", "${UNSET_VAR:-<postgres://localhost:5432/db>}", "<postgres://localhost:5432/db>"},
		{"plain brace — var unset, returns empty", "${UNSET_VAR}", ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_ = os.Unsetenv("UNSET_VAR")
			assert.Equal(t, tt.want, os.Expand(tt.template, expandWithDefault))
		})
	}
}
