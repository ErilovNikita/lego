package pdns

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"testing"

	"github.com/go-acme/lego/v5/challenge/dns01"
	"github.com/go-acme/lego/v5/internal/tester"
	"github.com/go-acme/lego/v5/providers/dns/pdns/internal"
	"github.com/stretchr/testify/require"
)

const envDomain = envNamespace + "DOMAIN"

var envTest = tester.NewEnvTest(
	EnvAPIURL,
	EnvAPIURLs,
	EnvAPIVersion,
	EnvAPIKey,
	EnvAPIKeys).
	WithDomain(envDomain).
	WithLiveTestRequirements(envDomain).
	WithLiveTestExtra(func() bool {
		return os.Getenv(envDomain) != "" &&
			(os.Getenv(EnvAPIURL) != "" || os.Getenv(EnvAPIURLs) != "") &&
			(os.Getenv(EnvAPIKey) != "" || os.Getenv(EnvAPIKeys) != "")
	})

func TestNewDNSProvider(t *testing.T) {
	testCases := []struct {
		desc     string
		envVars  map[string]string
		expected string
	}{
		{
			desc: "success with PDNS_API_URL + PDNS_API_KEY",
			envVars: map[string]string{
				EnvAPIKey:     "123",
				EnvAPIURL:     "http://example.com",
				EnvAPIVersion: "1",
			},
		},
		{
			desc: "success with PDNS_API_URLS + single PDNS_API_KEY",
			envVars: map[string]string{
				EnvAPIKey:     "123",
				EnvAPIURLs:    "http://example.com,http://example.net",
				EnvAPIVersion: "1",
			},
		},
		{
			desc: "success with PDNS_API_URLS + one PDNS_API_KEYS",
			envVars: map[string]string{
				EnvAPIKeys:    "123",
				EnvAPIURLs:    "http://example.com,http://example.net",
				EnvAPIVersion: "1",
			},
		},
		{
			desc: "success with PDNS_API_URLS + multiple PDNS_API_KEYS",
			envVars: map[string]string{
				EnvAPIKeys:    "123,456",
				EnvAPIURLs:    "http://example.com,http://example.net",
				EnvAPIVersion: "1",
			},
		},
		{
			desc: "missing credentials",
			envVars: map[string]string{
				EnvAPIKey:  "",
				EnvAPIKeys: "",
				EnvAPIURL:  "",
				EnvAPIURLs: "",
			},
			expected: "pdns: some credentials information are missing: PDNS_API_KEY,PDNS_API_URLS",
		},
		{
			desc: "missing api key",
			envVars: map[string]string{
				EnvAPIKey: "",
				EnvAPIURL: "http://example.com",
			},
			expected: "pdns: some credentials information are missing: PDNS_API_KEY",
		},
		{
			desc: "missing API URL",
			envVars: map[string]string{
				EnvAPIKey:  "123",
				EnvAPIURL:  "",
				EnvAPIURLs: "",
			},
			expected: "pdns: some credentials information are missing: PDNS_API_URLS",
		},
		{
			desc: "error when URL count does not match key count",
			envVars: map[string]string{
				EnvAPIKeys:    "123,456",
				EnvAPIURLs:    "http://example.com,http://example.net,http://example.org",
				EnvAPIVersion: "1",
			},
			expected: "pdns: API URL count (3) does not match API key count (2)",
		},
		{
			desc: "error when PDNS_API_URL and PDNS_API_URLS conflict",
			envVars: map[string]string{
				EnvAPIKey:     "123",
				EnvAPIURL:     "http://example.com",
				EnvAPIURLs:    "http://example.net",
				EnvAPIVersion: "1",
			},
			expected: "pdns: PDNS_API_URL and PDNS_API_URLS cannot be used together",
		},
	}

	for _, test := range testCases {
		t.Run(test.desc, func(t *testing.T) {
			defer envTest.RestoreEnv()

			envTest.ClearEnv()

			envTest.Apply(test.envVars)

			p, err := NewDNSProvider()

			if test.expected == "" {
				require.NoError(t, err)
				require.NotNil(t, p)
				require.NotNil(t, p.config)
				require.Len(t, p.clients, len(p.config.Hosts))
			} else {
				require.EqualError(t, err, test.expected)
			}
		})
	}
}

func TestNewDNSProviderConfig(t *testing.T) {
	testCases := []struct {
		desc             string
		apiKey           string
		apiKeys          []string
		customAPIVersion int
		host             *url.URL
		hosts            []*url.URL
		expectedClients  int
		expected         string
	}{
		{
			desc:             "success",
			apiKey:           "123",
			customAPIVersion: 1,
			host:             mustParse("http://example.com"),
			expectedClients:  1,
		},
		{
			desc:             "success custom API version",
			apiKey:           "123",
			customAPIVersion: 1,
			host:             mustParse("http://example.com"),
			expectedClients:  1,
		},
		{
			desc:             "success multiple API URLs",
			apiKey:           "123",
			customAPIVersion: 1,
			hosts: []*url.URL{
				mustParse("http://example.com"),
				mustParse("http://example.net"),
			},
			expectedClients: 2,
		},
		{
			desc:             "success multiple API URLs and one API key in APIKeys",
			apiKeys:          []string{"123"},
			customAPIVersion: 1,
			hosts: []*url.URL{
				mustParse("http://example.com"),
				mustParse("http://example.net"),
			},
			expectedClients: 2,
		},
		{
			desc:             "success multiple API URLs and multiple API keys",
			apiKeys:          []string{"123", "456"},
			customAPIVersion: 1,
			hosts: []*url.URL{
				mustParse("http://example.com"),
				mustParse("http://example.net"),
			},
			expectedClients: 2,
		},
		{
			desc:     "missing credentials",
			expected: "pdns: API key missing",
		},
		{
			desc:     "missing API key",
			apiKey:   "",
			host:     mustParse("http://example.com"),
			expected: "pdns: API key missing",
		},
		{
			desc:     "missing host",
			apiKey:   "123",
			expected: "pdns: API URL missing",
		},
		{
			desc:             "API URL count does not match API key count",
			apiKeys:          []string{"123", "456"},
			customAPIVersion: 1,
			hosts: []*url.URL{
				mustParse("http://example.com"),
				mustParse("http://example.net"),
				mustParse("http://example.org"),
			},
			expected: "pdns: API URL count (3) does not match API key count (2)",
		},
		{
			desc:             "Host and Hosts cannot be used together",
			apiKey:           "123",
			customAPIVersion: 1,
			host:             mustParse("http://example.com"),
			hosts: []*url.URL{
				mustParse("http://example.net"),
			},
			expected: "pdns: Host and Hosts cannot be used together",
		},
	}

	for _, test := range testCases {
		t.Run(test.desc, func(t *testing.T) {
			config := NewDefaultConfig()
			config.APIKey = test.apiKey
			config.APIKeys = test.apiKeys
			config.Host = test.host
			config.Hosts = test.hosts
			config.APIVersion = test.customAPIVersion

			p, err := NewDNSProviderConfig(config)

			if test.expected == "" {
				require.NoError(t, err)
				require.NotNil(t, p)
				require.NotNil(t, p.config)
				require.Len(t, p.clients, test.expectedClients)
			} else {
				require.EqualError(t, err, test.expected)
			}
		})
	}
}

func TestDNSProviderPresentMultipleEndpoints(t *testing.T) {
	first := newPowerDNSServer(t, "first-key", false, "REPLACE")
	second := newPowerDNSServer(t, "second-key", false, "REPLACE")

	config := NewDefaultConfig()
	config.APIVersion = 1
	config.APIKeys = []string{"first-key", "second-key"}
	config.Hosts = []*url.URL{mustParse(first.URL), mustParse(second.URL)}
	config.ServerName = "localhost"

	provider, err := NewDNSProviderConfig(config)
	require.NoError(t, err)

	info := dns01.ChallengeInfo{
		EffectiveFQDN: "_acme-challenge.example.org.",
		Value:         "test-value",
	}

	err = provider.presentAll(context.Background(), "example.org.", info)
	require.NoError(t, err)

	first.requireRequests(t)
	second.requireRequests(t)
}

func TestDNSProviderCleanUpMultipleEndpoints(t *testing.T) {
	first := newPowerDNSServer(t, "first-key", true, "DELETE")
	second := newPowerDNSServer(t, "second-key", true, "DELETE")

	config := NewDefaultConfig()
	config.APIVersion = 1
	config.APIKeys = []string{"first-key", "second-key"}
	config.Hosts = []*url.URL{mustParse(first.URL), mustParse(second.URL)}
	config.ServerName = "localhost"

	provider, err := NewDNSProviderConfig(config)
	require.NoError(t, err)

	info := dns01.ChallengeInfo{
		EffectiveFQDN: "_acme-challenge.example.org.",
		Value:         "test-value",
	}

	err = provider.cleanUpAll(context.Background(), "example.org.", info)
	require.NoError(t, err)

	first.requireRequests(t)
	second.requireRequests(t)
}

func TestParseURLs(t *testing.T) {
	testCases := []struct {
		desc     string
		raw      string
		expected []*url.URL
		err      string
	}{
		{
			desc: "single URL",
			raw:  "http://example.com",
			expected: []*url.URL{
				mustParse("http://example.com"),
			},
		},
		{
			desc: "multiple URLs",
			raw:  "http://example.com, http://example.net/",
			expected: []*url.URL{
				mustParse("http://example.com"),
				mustParse("http://example.net/"),
			},
		},
		{
			desc: "empty",
			raw:  "",
			err:  "API URL missing",
		},
		{
			desc: "invalid URL",
			raw:  "http://[::1",
			err:  "parse \"http://[::1\": missing ']' in host",
		},
	}

	for _, test := range testCases {
		t.Run(test.desc, func(t *testing.T) {
			actual, err := parseURLs(test.raw)

			if test.err == "" {
				require.NoError(t, err)
				require.Equal(t, test.expected, actual)
			} else {
				require.EqualError(t, err, test.err)
			}
		})
	}
}

func newPowerDNSServer(t *testing.T, expectedAPIKey string, existingTXT bool, expectedChangeType string) *powerDNSServer {
	t.Helper()

	server := &powerDNSServer{
		expectedAPIKey:     expectedAPIKey,
		existingTXT:        existingTXT,
		expectedChangeType: expectedChangeType,
	}
	server.Server = httptest.NewServer(http.HandlerFunc(server.handle))
	t.Cleanup(server.Close)

	return server
}

type powerDNSServer struct {
	*httptest.Server

	expectedAPIKey     string
	existingTXT        bool
	expectedChangeType string
	getZoneCalled      bool
	updateCalled       bool
	notifyCalled       bool
}

func (s *powerDNSServer) handle(w http.ResponseWriter, r *http.Request) {
	if r.Header.Get(internal.APIKeyHeader) != s.expectedAPIKey {
		http.Error(w, "unexpected API key", http.StatusUnauthorized)
		return
	}

	switch {
	case r.Method == http.MethodGet && r.URL.Path == "/api/v1/servers/localhost/zones/example.org.":
		s.getZoneCalled = true
		zone := internal.HostedZone{
			ID:   "example.org.",
			Name: "example.org.",
			Kind: "Master",
		}
		if s.existingTXT {
			zone.RRSets = []internal.RRSet{{
				Name: "_acme-challenge.example.org.",
				Type: "TXT",
				Records: []internal.Record{{
					Content: `"test-value"`,
				}},
			}}
		}

		writeJSON(w, zone)
	case r.Method == http.MethodPatch && r.URL.Path == "/api/v1/servers/localhost/zones/example.org.":
		s.updateCalled = true
		var rrSets internal.RRSets
		err := json.NewDecoder(r.Body).Decode(&rrSets)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}

		if len(rrSets.RRSets) != 1 ||
			rrSets.RRSets[0].Name != "_acme-challenge.example.org." ||
			rrSets.RRSets[0].ChangeType != s.expectedChangeType {
			http.Error(w, "unexpected rrset", http.StatusBadRequest)
			return
		}

		writeJSON(w, internal.HostedZone{
			ID:   "example.org.",
			Name: "example.org.",
			Kind: "Master",
		})
	case r.Method == http.MethodPut && r.URL.Path == "/api/v1/servers/localhost/zones/example.org./notify":
		s.notifyCalled = true
		w.WriteHeader(http.StatusNoContent)
	default:
		http.NotFound(w, r)
	}
}

func (s *powerDNSServer) requireRequests(t *testing.T) {
	t.Helper()

	require.True(t, s.getZoneCalled)
	require.True(t, s.updateCalled)
	require.True(t, s.notifyCalled)
}

func writeJSON(w http.ResponseWriter, value any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(value)
}

func TestLivePresentAndCleanup(t *testing.T) {
	if !envTest.IsLiveTest() {
		t.Skip("skipping live test")
	}

	envTest.RestoreEnv()

	provider, err := NewDNSProvider()
	require.NoError(t, err)

	err = provider.Present(t.Context(), envTest.GetDomain(), "", "123d==")
	require.NoError(t, err)
	err = provider.Present(t.Context(), envTest.GetDomain(), "", "123e==")
	require.NoError(t, err)

	err = provider.CleanUp(t.Context(), envTest.GetDomain(), "", "123d==")
	require.NoError(t, err)
	err = provider.CleanUp(t.Context(), envTest.GetDomain(), "", "123e==")
	require.NoError(t, err)
}

func mustParse(rawURL string) *url.URL {
	u, err := url.Parse(rawURL)
	if err != nil {
		panic(err)
	}

	return u
}
