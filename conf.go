package main

import (
	"encoding/json"
	"io/ioutil"
)

const (
	TARGET_DROP int = iota
	TARGET_REJECT
	TARGET_ACCEPT
	TARGET_LOG
	TARGET_ULOG
)

type FirewallRule struct {
	target   int
	protocol string
	port     string
	mask     string
	ipset    string
}

type FirewallRuleset struct {
	name               string
	emptyrulesetpolicy string
	rules              []FirewallRule
}

func parse_firewall_ruleset(rulesetname string) {

}

type Config struct {
	SSLCert                string
	SSLKey                 string
	ClientTimeoutInMinutes int
	// Redirects HTTP URLs to HTTPS
	RedirectHttpToHttps bool
	// Redirects HTTP URLs to the gateway URL instead of modifying the HTTP page.
	RedirectToGateway bool
	// Hostname for the gateway. If empty, gateway IP address is used.
	GatewayHostname string
	// Name of the gateway. This is used in the login page.
	GatewayName string
}

func ReadConfig(c *Config) error {
	raw, err := ioutil.ReadFile("./config.json")
	if err != nil {
		panic("Could not read configuration")
	}
	return json.Unmarshal(raw, c)
}
