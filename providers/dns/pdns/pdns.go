// Package pdns implements a DNS provider for solving the DNS-01 challenge using PowerDNS nameserver.
package pdns

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/go-acme/lego/v5/challenge"
	"github.com/go-acme/lego/v5/challenge/dns01"
	"github.com/go-acme/lego/v5/log"
	"github.com/go-acme/lego/v5/platform/env"
	"github.com/go-acme/lego/v5/providers/dns/internal/clientdebug"
	"github.com/go-acme/lego/v5/providers/dns/pdns/internal"
)

// Environment variables names.
const (
	envNamespace = "PDNS_"

	EnvAPIKey  = envNamespace + "API_KEY"
	EnvAPIKeys = envNamespace + "API_KEYS"
	EnvAPIURL  = envNamespace + "API_URL"
	EnvAPIURLs = envNamespace + "API_URLS"

	EnvTTL                = envNamespace + "TTL"
	EnvAPIVersion         = envNamespace + "API_VERSION"
	EnvPropagationTimeout = envNamespace + "PROPAGATION_TIMEOUT"
	EnvPollingInterval    = envNamespace + "POLLING_INTERVAL"
	EnvHTTPTimeout        = envNamespace + "HTTP_TIMEOUT"
	EnvServerName         = envNamespace + "SERVER_NAME"
)

var _ challenge.ProviderTimeout = (*DNSProvider)(nil)

// Config is used to configure the creation of the DNSProvider.
type Config struct {
	APIKey             string
	APIKeys            []string
	Host               *url.URL
	Hosts              []*url.URL
	ServerName         string
	APIVersion         int
	PropagationTimeout time.Duration
	PollingInterval    time.Duration
	TTL                int
	HTTPClient         *http.Client
}

// NewDefaultConfig returns a default configuration for the DNSProvider.
func NewDefaultConfig() *Config {
	return &Config{
		ServerName:         env.GetOrDefaultString(EnvServerName, "localhost"),
		APIVersion:         env.GetOrDefaultInt(EnvAPIVersion, 0),
		TTL:                env.GetOrDefaultInt(EnvTTL, dns01.DefaultTTL),
		PropagationTimeout: env.GetOrDefaultSecond(EnvPropagationTimeout, 120*time.Second),
		PollingInterval:    env.GetOrDefaultSecond(EnvPollingInterval, 2*time.Second),
		HTTPClient: &http.Client{
			Timeout: env.GetOrDefaultSecond(EnvHTTPTimeout, 30*time.Second),
		},
	}
}

// DNSProvider implements the challenge.Provider interface.
type DNSProvider struct {
	config  *Config
	clients []*internal.Client
}

// NewDNSProvider returns a DNSProvider instance configured for pdns.
// Credentials must be passed in the environment variable:
// PDNS_API_URLS (or PDNS_API_URL) and PDNS_API_KEYS (or PDNS_API_KEY).
func NewDNSProvider() (*DNSProvider, error) {
	apiURL := env.GetOrFile(EnvAPIURL)
	apiURLs := env.GetOrFile(EnvAPIURLs)
	apiKey := env.GetOrFile(EnvAPIKey)
	apiKeys := env.GetOrFile(EnvAPIKeys)

	if apiURL != "" && apiURLs != "" {
		return nil, fmt.Errorf("pdns: %s and %s cannot be used together", EnvAPIURL, EnvAPIURLs)
	}

	var missingEnvVars []string
	if apiKey == "" && apiKeys == "" {
		missingEnvVars = append(missingEnvVars, EnvAPIKey)
	}
	if apiURL == "" && apiURLs == "" {
		missingEnvVars = append(missingEnvVars, EnvAPIURLs)
	}
	if len(missingEnvVars) > 0 {
		return nil, fmt.Errorf("pdns: some credentials information are missing: %s", strings.Join(missingEnvVars, ","))
	}

	if apiURLs == "" {
		apiURLs = apiURL
	}

	hostURLs, err := parseURLs(apiURLs)
	if err != nil {
		return nil, fmt.Errorf("pdns: %w", err)
	}

	keys, err := parseKeys(apiKey, apiKeys, len(hostURLs))
	if err != nil {
		return nil, fmt.Errorf("pdns: %w", err)
	}

	config := NewDefaultConfig()
	config.Hosts = hostURLs
	config.APIKey = apiKey
	config.APIKeys = keys

	return NewDNSProviderConfig(config)
}

// NewDNSProviderConfig return a DNSProvider instance configured for pdns.
func NewDNSProviderConfig(config *Config) (*DNSProvider, error) {
	if config == nil {
		return nil, errors.New("pdns: the configuration of the DNS provider is nil")
	}

	if config.APIKey == "" && len(config.APIKeys) == 0 {
		return nil, errors.New("pdns: API key missing")
	}

	if config.Host != nil && len(config.Hosts) > 0 {
		return nil, errors.New("pdns: Host and Hosts cannot be used together")
	}

	hosts := config.Hosts
	if len(hosts) == 0 && config.Host != nil {
		hosts = []*url.URL{config.Host}
	}

	if len(hosts) == 0 {
		return nil, errors.New("pdns: API URL missing")
	}

	keys := config.APIKeys
	if len(keys) == 0 {
		keys = repeatString(config.APIKey, len(hosts))
	} else if len(keys) == 1 {
		keys = repeatString(keys[0], len(hosts))
	}

	if len(keys) != len(hosts) {
		return nil, fmt.Errorf("pdns: API URL count (%d) does not match API key count (%d)", len(hosts), len(keys))
	}

	var clients []*internal.Client

	for i, host := range hosts {
		if host == nil || host.Host == "" {
			return nil, errors.New("pdns: API URL missing")
		}

		if keys[i] == "" {
			return nil, errors.New("pdns: API key missing")
		}

		client := internal.NewClient(host, config.ServerName, config.APIVersion, keys[i])

		if config.HTTPClient != nil {
			client.HTTPClient = config.HTTPClient
		}

		client.HTTPClient = clientdebug.Wrap(client.HTTPClient)

		if config.APIVersion <= 0 {
			err := client.SetAPIVersion(context.Background())
			if err != nil {
				log.Warn("pdns: failed to get API version.", log.ErrorAttr(err))
			}
		}

		clients = append(clients, client)
	}

	config.Hosts = hosts
	config.Host = hosts[0]
	config.APIKeys = keys

	return &DNSProvider{config: config, clients: clients}, nil
}

// Timeout returns the timeout and interval to use when checking for DNS propagation.
// Adjusting here to cope with spikes in propagation times.
func (d *DNSProvider) Timeout() (timeout, interval time.Duration) {
	return d.config.PropagationTimeout, d.config.PollingInterval
}

// Present creates a TXT record to fulfill the dns-01 challenge.
func (d *DNSProvider) Present(ctx context.Context, domain, token, keyAuth string) error {
	info := dns01.GetChallengeInfo(ctx, domain, keyAuth)

	authZone, err := dns01.DefaultClient().FindZoneByFqdn(ctx, info.EffectiveFQDN)
	if err != nil {
		return fmt.Errorf("pdns: could not find zone for domain %q: %w", domain, err)
	}

	return d.presentAll(ctx, authZone, info)
}

// CleanUp removes the TXT record matching the specified parameters.
func (d *DNSProvider) CleanUp(ctx context.Context, domain, token, keyAuth string) error {
	info := dns01.GetChallengeInfo(ctx, domain, keyAuth)

	authZone, err := dns01.DefaultClient().FindZoneByFqdn(ctx, info.EffectiveFQDN)
	if err != nil {
		return fmt.Errorf("pdns: could not find zone for domain %q: %w", domain, err)
	}

	return d.cleanUpAll(ctx, authZone, info)
}

func (d *DNSProvider) presentAll(ctx context.Context, authZone string, info dns01.ChallengeInfo) error {
	for i, client := range d.clients {
		err := d.present(ctx, client, authZone, info)
		if err != nil {
			return fmt.Errorf("pdns: API URL %d: %w", i+1, err)
		}
	}

	return nil
}

func (d *DNSProvider) cleanUpAll(ctx context.Context, authZone string, info dns01.ChallengeInfo) error {
	for i, client := range d.clients {
		err := d.cleanUp(ctx, client, authZone, info)
		if err != nil {
			return fmt.Errorf("pdns: API URL %d: %w", i+1, err)
		}
	}

	return nil
}

func (d *DNSProvider) present(ctx context.Context, client *internal.Client, authZone string, info dns01.ChallengeInfo) error {
	zone, err := client.GetHostedZone(ctx, authZone)
	if err != nil {
		return fmt.Errorf("get hosted zone for %s: %w", authZone, err)
	}

	name := info.EffectiveFQDN
	if client.APIVersion() == 0 {
		// pre-v1 API wants non-fqdn
		name = dns01.UnFqdn(info.EffectiveFQDN)
	}

	// Look for existing records.
	existingRRSet := findTxtRecord(zone, info.EffectiveFQDN)

	var records []internal.Record
	if existingRRSet != nil {
		records = existingRRSet.Records
	}

	records = append(records, internal.Record{
		Content:  strconv.Quote(info.Value),
		Disabled: false,

		// pre-v1 API
		Type: "TXT",
		Name: name,
		TTL:  d.config.TTL,
	})

	rrSets := internal.RRSets{
		RRSets: []internal.RRSet{{
			Name:       name,
			ChangeType: "REPLACE",
			Type:       "TXT",
			Kind:       "Master",
			TTL:        d.config.TTL,
			Records:    records,
		}},
	}

	err = client.UpdateRecords(ctx, zone, rrSets)
	if err != nil {
		return fmt.Errorf("update records: %w", err)
	}

	err = client.Notify(ctx, zone)
	if err != nil {
		return fmt.Errorf("notify: %w", err)
	}

	return nil
}

func (d *DNSProvider) cleanUp(ctx context.Context, client *internal.Client, authZone string, info dns01.ChallengeInfo) error {
	zone, err := client.GetHostedZone(ctx, authZone)
	if err != nil {
		return fmt.Errorf("get hosted zone for %s: %w", authZone, err)
	}

	// Look for existing records.
	set := findTxtRecord(zone, info.EffectiveFQDN)
	if set == nil {
		return fmt.Errorf("no existing record found for %s", info.EffectiveFQDN)
	}

	var records []internal.Record

	for _, r := range set.Records {
		if r.Content != strconv.Quote(info.Value) {
			records = append(records, r)
		}
	}

	rrSet := internal.RRSet{
		Name: set.Name,
		Type: set.Type,
	}

	if len(records) > 0 {
		rrSet.ChangeType = "REPLACE"
		rrSet.TTL = d.config.TTL
		rrSet.Records = records
	} else {
		rrSet.ChangeType = "DELETE"
	}

	err = client.UpdateRecords(ctx, zone, internal.RRSets{RRSets: []internal.RRSet{rrSet}})
	if err != nil {
		return fmt.Errorf("update records: %w", err)
	}

	err = client.Notify(ctx, zone)
	if err != nil {
		return fmt.Errorf("notify: %w", err)
	}

	return nil
}

func parseURLs(raw string) ([]*url.URL, error) {
	var urls []*url.URL

	for rawURL := range strings.SplitSeq(raw, ",") {
		rawURL = strings.TrimSpace(rawURL)
		if rawURL == "" {
			continue
		}

		parsedURL, err := url.Parse(rawURL)
		if err != nil {
			return nil, err
		}

		urls = append(urls, parsedURL)
	}

	if len(urls) == 0 {
		return nil, errors.New("API URL missing")
	}

	return urls, nil
}

func parseKeys(apiKey, apiKeys string, count int) ([]string, error) {
	if apiKeys == "" {
		return repeatString(apiKey, count), nil
	}

	keys := splitCommaSeparated(apiKeys)
	if len(keys) == 1 {
		return repeatString(keys[0], count), nil
	}

	if len(keys) != count {
		return nil, fmt.Errorf("API URL count (%d) does not match API key count (%d)", count, len(keys))
	}

	return keys, nil
}

func repeatString(value string, count int) []string {
	values := make([]string, count)
	for i := range values {
		values[i] = value
	}

	return values
}

func splitCommaSeparated(raw string) []string {
	var values []string

	for value := range strings.SplitSeq(raw, ",") {
		value = strings.TrimSpace(value)
		if value == "" {
			continue
		}

		values = append(values, value)
	}

	return values
}

func findTxtRecord(zone *internal.HostedZone, fqdn string) *internal.RRSet {
	for _, set := range zone.RRSets {
		if set.Type == "TXT" && (set.Name == dns01.UnFqdn(fqdn) || set.Name == fqdn) {
			return &set
		}
	}

	return nil
}
