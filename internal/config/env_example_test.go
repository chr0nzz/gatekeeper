package config

import (
	"os"
	"reflect"
	"regexp"
	"strings"
	"testing"
)

// envVarsInConfig returns every environment variable the Config struct reads.
func envVarsInConfig() []string {
	var out []string
	t := reflect.TypeOf(Config{})
	for i := 0; i < t.NumField(); i++ {
		tag := t.Field(i).Tag.Get("env")
		if tag == "" {
			continue
		}
		out = append(out, strings.Split(tag, ",")[0])
	}
	return out
}

// .env.example is the first thing an operator reads. A variable missing from it
// is a variable nobody knows exists.
func TestEnvExampleCoversEveryVariable(t *testing.T) {
	body, err := os.ReadFile("../../.env.example")
	if err != nil {
		t.Fatalf("read .env.example: %v", err)
	}
	text := string(body)

	for _, name := range envVarsInConfig() {
		if !regexp.MustCompile(`(?m)^#?\s*` + regexp.QuoteMeta(name) + `=`).MatchString(text) {
			t.Errorf("%s is read by Config but is not in .env.example", name)
		}
	}
}

// The reverse: a variable left in the file after it was removed from the code
// sends operators chasing a setting that does nothing.
func TestEnvExampleHasNoUnknownVariables(t *testing.T) {
	body, err := os.ReadFile("../../.env.example")
	if err != nil {
		t.Fatalf("read .env.example: %v", err)
	}

	known := map[string]bool{}
	for _, name := range envVarsInConfig() {
		known[name] = true
	}

	assignment := regexp.MustCompile(`^([A-Z][A-Z0-9_]*)=`)
	for _, line := range strings.Split(string(body), "\n") {
		m := assignment.FindStringSubmatch(strings.TrimSpace(line))
		if m != nil && !known[m[1]] {
			t.Errorf("%s is in .env.example but no longer read by Config", m[1])
		}
	}
}
