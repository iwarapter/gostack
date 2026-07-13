package main

import (
	"os"
	"testing"
)

func TestExpandParam(t *testing.T) {
	exp := func(s string) string { return os.Expand(s, expandParam) }

	tests := []struct {
		name  string
		set   bool
		value string
		input string
		want  string
	}{
		{"plain braces set", true, "bar", "${FOO}", "bar"},
		{"plain no-braces set", true, "bar", "$FOO", "bar"},
		{"plain unset", false, "", "${FOO}", ""},

		{"colon-dash unset", false, "", "${FOO:-def}", "def"},
		{"colon-dash empty", true, "", "${FOO:-def}", "def"},
		{"colon-dash set", true, "bar", "${FOO:-def}", "bar"},

		{"dash unset", false, "", "${FOO-def}", "def"},
		{"dash empty", true, "", "${FOO-def}", ""},
		{"dash set", true, "bar", "${FOO-def}", "bar"},

		{"colon-plus set", true, "bar", "${FOO:+alt}", "alt"},
		{"colon-plus empty", true, "", "${FOO:+alt}", ""},
		{"colon-plus unset", false, "", "${FOO:+alt}", ""},

		{"plus set", true, "bar", "${FOO+alt}", "alt"},
		{"plus empty", true, "", "${FOO+alt}", "alt"},
		{"plus unset", false, "", "${FOO+alt}", ""},

		{"url default unset", false, "", "${FOO:-http://localhost:4000}", "http://localhost:4000"},
		{"url default set", true, "http://example.com", "${FOO:-http://localhost:4000}", "http://example.com"},

		{"embedded", false, "", "dir/${FOO:-fallback}/end", "dir/fallback/end"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			os.Unsetenv("FOO")
			if tt.set {
				t.Setenv("FOO", tt.value)
			}
			if got := exp(tt.input); got != tt.want {
				t.Errorf("expand(%q) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}
