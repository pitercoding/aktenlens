package main

import (
	"reflect"
	"strings"
	"testing"
)

// fakeEnv builds a getenv function from a map.
func fakeEnv(vars map[string]string) func(string) string {
	return func(key string) string { return vars[key] }
}

func TestLoadConfig(t *testing.T) {
	cases := []struct {
		name string
		env  map[string]string
		want config
	}{
		// Nothing set: the safe production defaults.
		{"defaults", nil, config{SecureCookies: true}},
		// make exports unset variables as empty strings, which must mean "default".
		{"empty values mean the defaults", map[string]string{
			"COOKIE_SECURE": "", "TRUSTED_PROXY_HOPS": "", "TRUSTED_ORIGINS": "",
		}, config{SecureCookies: true}},

		{"cookies off for local HTTP development", map[string]string{"COOKIE_SECURE": "false"}, config{SecureCookies: false}},
		{"cookies explicitly on", map[string]string{"COOKIE_SECURE": "true"}, config{SecureCookies: true}},
		{"case and spaces are ignored", map[string]string{"COOKIE_SECURE": " FALSE "}, config{SecureCookies: false}},

		{"no proxy", map[string]string{"TRUSTED_PROXY_HOPS": "0"}, config{SecureCookies: true, TrustedProxyHops: 0}},
		{"one proxy", map[string]string{"TRUSTED_PROXY_HOPS": "1"}, config{SecureCookies: true, TrustedProxyHops: 1}},
		{"the largest allowed number of proxies", map[string]string{"TRUSTED_PROXY_HOPS": "10"}, config{SecureCookies: true, TrustedProxyHops: 10}},

		{"one trusted origin", map[string]string{"TRUSTED_ORIGINS": "https://app.example.com"}, config{
			SecureCookies: true, TrustedOrigins: []string{"https://app.example.com"},
		}},
		{"several origins, with spaces and a trailing comma", map[string]string{
			"TRUSTED_ORIGINS": " https://app.example.com , http://localhost:3000 ,",
		}, config{
			SecureCookies:  true,
			TrustedOrigins: []string{"https://app.example.com", "http://localhost:3000"},
		}},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := loadConfig(fakeEnv(tc.env))
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if !reflect.DeepEqual(got, tc.want) {
				t.Fatalf("expected %+v, got %+v", tc.want, got)
			}
		})
	}
}

// A wrong setting must stop the API at startup, and the error must say which
// variable is wrong.
func TestLoadConfigRejectsInvalidValues(t *testing.T) {
	cases := []struct {
		name     string
		variable string
		value    string
	}{
		{"cookie flag: yes", "COOKIE_SECURE", "yes"},
		{"cookie flag: 1", "COOKIE_SECURE", "1"},
		{"cookie flag: typo", "COOKIE_SECURE", "flase"},

		{"proxies: negative", "TRUSTED_PROXY_HOPS", "-1"},
		{"proxies: not a number", "TRUSTED_PROXY_HOPS", "abc"},
		{"proxies: decimal", "TRUSTED_PROXY_HOPS", "1.5"},
		{"proxies: too many", "TRUSTED_PROXY_HOPS", "11"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := loadConfig(fakeEnv(map[string]string{tc.variable: tc.value}))

			if err == nil {
				t.Fatal("expected an error")
			}
			if !strings.Contains(err.Error(), tc.variable) {
				t.Fatalf("the error should name %s, got %q", tc.variable, err)
			}
		})
	}
}
