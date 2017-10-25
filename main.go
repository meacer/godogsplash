package main

import (
	"bufio"
	"crypto/tls"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"strings"
	"time"
)

var (
	FW_MARK_PREAUTHENTICATED int
	FW_MARK_AUTHENTICATED    int
	FW_MARK_BLOCKED          int
	FW_MARK_TRUSTED          int
	FW_MARK_MASK             int

	markop   = "--or_mark"
	markmask = ""
)

const (
	CHAIN_TO_INTERNET       = "ndsNET"
	CHAIN_TO_ROUTER         = "ndsRTR"
	CHAIN_TRUSTED_TO_ROUTER = "ndsTRT"
	CHAIN_OUTGOING          = "ndsOUT"
	CHAIN_INCOMING          = "ndsINC"
	CHAIN_AUTHENTICATED     = "ndsAUT"
	CHAIN_PREAUTHENTICATED  = "ndsPRE"
	CHAIN_BLOCKED           = "ndsBLK"
	CHAIN_ALLOWED           = "ndsALW"
	CHAIN_TRUSTED           = "ndsTRU"
)

func _iptables_init_marks() {
	FW_MARK_PREAUTHENTICATED = 0
	FW_MARK_BLOCKED = 0x100
	FW_MARK_TRUSTED = 0x200
	FW_MARK_AUTHENTICATED = 0x400
	FW_MARK_MASK = FW_MARK_BLOCKED | FW_MARK_TRUSTED | FW_MARK_AUTHENTICATED
}

func do_command(cmd string) int {
	fmt.Printf("# RUN:\n%v\n", cmd)
	out, err := exec.Command("sh", "-c", cmd).Output()
	if err != nil {
		fmt.Printf("DoCommand error: %v, cmd: %v\n", err, cmd)
		return 1
	}
	if out != nil && len(out) != 0 {
		fmt.Printf("DoCommand result nonzero, value: %v\n", out)
		return 1
	}
	return 0
}

func iptables_do_command(format string, a ...interface{}) int {
	cmd := fmt.Sprintf(format, a...)
	rc := do_command("iptables --wait " + cmd)
	if rc != 0 {
		panic(fmt.Sprintf("Failed to run iptables command, return code: %v\n", rc))
	}
	return rc
}

func is_empty_ruleset(ruleset string) bool {
	if ruleset == "trusted-users-to-router" {
		return true
	}
	if ruleset == "users-to-router" {
		return false
	}
	if ruleset == "trusted-users" {
		return true
	}
	if ruleset == "authenticated-users" {
		return false
	}
	if ruleset == "preauthenticated-users" {
		return false
	}
	panic(fmt.Sprintf("Invalid ruleset name: %v", ruleset))
	return false
}

func _iptables_check_mark_masking() {
	/* See if kernel supports mark or-ing */
	if 0 == iptables_do_command("-t mangle -I PREROUTING 1 -j MARK --or-mark 0x%x", FW_MARK_BLOCKED) {
		iptables_do_command("-t mangle -D PREROUTING 1") /* delete test rule we just inserted */
		fmt.Printf("Kernel supports --or-mark.\n")
		markop = "--or-mark"
	} else {
		fmt.Printf("Kernel does not support iptables --or-mark.  Using --set-mark instead.\n")
		markop = "--set-mark"
	}

	/* See if kernel supports mark masking */
	if 0 == iptables_do_command("-t filter -I FORWARD 1 -m mark --mark 0x%x/0x%x -j REJECT", FW_MARK_BLOCKED, FW_MARK_MASK) {
		iptables_do_command("-t filter -D FORWARD 1") /* delete test rule we just inserted */
		fmt.Printf("Kernel supports mark masking.\n")
		markmask = fmt.Sprintf("/0x%x", FW_MARK_MASK)
	} else {
		fmt.Printf("Kernel does not support iptables mark masking.  Using empty mask.\n")
		markmask = ""
	}
}

func get_empty_ruleset_policy(ruleset string) string {
	if ruleset == "trusted-users-to-router" {
		return "ACCEPT"
	}
	if ruleset == "trusted-users" {
		return "ACCEPT"
	}
	panic(fmt.Sprintf("Invalid ruleset name: %v", ruleset))
	return ""
}

func _iptables_compile(table string, chain string, rule FirewallRule) string {
	mode := ""
	switch rule.target {
	case TARGET_DROP:
		mode = "DROP"
	case TARGET_REJECT:
		mode = "REJECT"
	case TARGET_ACCEPT:
		mode = "ACCEPT"
	case TARGET_LOG:
		mode = "LOG"
	case TARGET_ULOG:
		mode = "ULOG"
	}

	command := fmt.Sprintf("-t %s -A %s ", table, chain)
	if rule.mask != "" {
		command = fmt.Sprintf("%s -d %s", command, rule.mask)
	}
	if rule.protocol != "" {
		command = fmt.Sprintf("%s -p %s", command, rule.protocol)
	}
	if rule.port != "" {
		command = fmt.Sprintf("%s --dport %s", command, rule.port)
	}
	if rule.ipset != "" {
		command = fmt.Sprintf("%s -m set --match-set %s dst", command, rule.ipset)
	}
	command = fmt.Sprintf("%s -j%s", command, mode)
	return command
}

func _iptables_append_ruleset(table string, ruleset string, chain string) int {
	// TODO: Implement.
	rules := []FirewallRule{}
	if ruleset == "users-to-router" {
		rules = []FirewallRule{
			FirewallRule{TARGET_ACCEPT, "udp", "53", "0.0.0.0/0", ""},
			FirewallRule{TARGET_ACCEPT, "tcp", "53", "0.0.0.0/0", ""},
			FirewallRule{TARGET_ACCEPT, "udp", "67", "0.0.0.0/0", ""},
			// TODO: Remove:
			FirewallRule{TARGET_ACCEPT, "tcp", "22", "0.0.0.0/0", ""},
			FirewallRule{TARGET_ACCEPT, "tcp", "80", "0.0.0.0/0", ""},
			FirewallRule{TARGET_ACCEPT, "tcp", "443", "0.0.0.0/0", ""},
		}
	} else if ruleset == "authenticated-users" {
		rules = []FirewallRule{
			FirewallRule{TARGET_REJECT, "" /* protocol */, "" /* port */, "192.168.0.0/16", ""},
			FirewallRule{TARGET_REJECT, "" /* protocol */, "" /* port */, "10.0.0.0/8", ""},
			FirewallRule{TARGET_ACCEPT, "tcp" /* protocol */, "53" /* port */, "0.0.0.0/0", ""},
			FirewallRule{TARGET_ACCEPT, "udp" /* protocol */, "53" /* port */, "0.0.0.0/0", ""},
			FirewallRule{TARGET_ACCEPT, "tcp" /* protocol */, "80" /* port */, "0.0.0.0/0", ""},
			// TODO: Remove:
			FirewallRule{TARGET_ACCEPT, "tcp" /* protocol */, "443" /* port */, "0.0.0.0/0", ""},
			FirewallRule{TARGET_ACCEPT, "tcp" /* protocol */, "22" /* port */, "0.0.0.0/0", ""},
		}
	} else if ruleset == "preauthenticated-users" {
		rules = []FirewallRule{
			FirewallRule{TARGET_ACCEPT, "tcp" /* protocol */, "53" /* port */, "0.0.0.0/0", ""},
			FirewallRule{TARGET_ACCEPT, "udp" /* protocol */, "53" /* port */, "0.0.0.0/0", ""},
		}
	} else {
		panic("Invalid ruleset: " + ruleset)
	}
	ret := 0
	for _, rule := range rules {
		cmd := _iptables_compile(table, chain, rule)
		fmt.Printf("Loading rule \"%s\" into table %s, chain %s\n", cmd, table, chain)
		ret |= iptables_do_command(cmd)
	}
	return ret
}

func FirewallInit() {
	_iptables_init_marks()
	_iptables_check_mark_masking()
}

func iptables_init() {
	//iptables.getIPTablesHasCheckCommand("test")

	gw_interface := "wlan0"
	gw_iprange := "0.0.0.0/0"
	gw_address := "192.168.24.1"
	gw_port := 2050
	gw_port_ssl := 2051

	set_mss := true
	mss_value := 0

	FirewallInit()

	// Set up mangle table chains and rules.
	// Create new chains in the mangle table.
	iptables_do_command("-t mangle -N " + CHAIN_TRUSTED)  /* for marking trusted packets */
	iptables_do_command("-t mangle -N " + CHAIN_BLOCKED)  /* for marking blocked packets */
	iptables_do_command("-t mangle -N " + CHAIN_INCOMING) /* for counting incoming packets */
	iptables_do_command("-t mangle -N " + CHAIN_OUTGOING) /* for marking authenticated packets, and for counting outgoing packets */
	// Assign jumps to these new chains.
	iptables_do_command("-t mangle -I PREROUTING 1 -i %s -s %s -j "+CHAIN_OUTGOING, gw_interface, gw_iprange)
	iptables_do_command("-t mangle -I PREROUTING 2 -i %s -s %s -j "+CHAIN_BLOCKED, gw_interface, gw_iprange)
	iptables_do_command("-t mangle -I PREROUTING 3 -i %s -s %s -j "+CHAIN_TRUSTED, gw_interface, gw_iprange)
	iptables_do_command("-t mangle -I POSTROUTING 1 -o %s -d %s -j "+CHAIN_INCOMING, gw_interface, gw_iprange)

	/* Rules to mark as trusted MAC address packets in mangle PREROUTING */
	//for (; pt != NULL; pt = pt->next) {
	//  rc |= iptables_trust_mac(pt->mac);
	//}

	// TODO: Mac list...

	// Set up for traffic control...

	// End of mangle table chains and rules.

	// Create new chains in nat table.
	rc := iptables_do_command("-t nat -N " + CHAIN_OUTGOING)

	/* packets coming in on gw_interface jump to CHAIN_OUTGOING */
	rc |= iptables_do_command("-t nat -I PREROUTING -i %s -s %s -j "+CHAIN_OUTGOING, gw_interface, gw_iprange)
	/* CHAIN_OUTGOING, packets marked TRUSTED  ACCEPT */
	rc |= iptables_do_command("-t nat -A "+CHAIN_OUTGOING+" -m mark --mark 0x%x%s -j ACCEPT", FW_MARK_TRUSTED, markmask)
	/* CHAIN_OUTGOING, packets marked AUTHENTICATED  ACCEPT */
	rc |= iptables_do_command("-t nat -A "+CHAIN_OUTGOING+" -m mark --mark 0x%x%s -j ACCEPT", FW_MARK_AUTHENTICATED, markmask)
	/* CHAIN_OUTGOING, append the "preauthenticated-users" ruleset */
	rc |= _iptables_append_ruleset("nat", "preauthenticated-users", CHAIN_OUTGOING)

	/* CHAIN_OUTGOING, packets for tcp port 80, redirect to gw_port on primary address for the iface */
	rc |= iptables_do_command("-t nat -A "+CHAIN_OUTGOING+" -p tcp --dport 80 -j DNAT --to-destination %s:%d", gw_address, gw_port)
	/* CHAIN_OUTGOING, packets for tcp port 443, redirect to gw_port_ssl on primary address for the iface */
	rc |= iptables_do_command("-t nat -A "+CHAIN_OUTGOING+" -p tcp --dport 443 -j DNAT --to-destination %s:%d", gw_address, gw_port_ssl)

	/* CHAIN_OUTGOING, other packets  ACCEPT */
	rc |= iptables_do_command("-t nat -A " + CHAIN_OUTGOING + " -j ACCEPT")

	// * End of nat table chains and rules.

	// Set up filter table chains and rules.
	/* Create new chains in the filter table */
	rc |= iptables_do_command("-t filter -N " + CHAIN_TO_INTERNET)
	rc |= iptables_do_command("-t filter -N " + CHAIN_TO_ROUTER)
	rc |= iptables_do_command("-t filter -N " + CHAIN_AUTHENTICATED)
	rc |= iptables_do_command("-t filter -N " + CHAIN_TRUSTED)
	rc |= iptables_do_command("-t filter -N " + CHAIN_TRUSTED_TO_ROUTER)

	/*
	 * filter INPUT chain
	 */
	/* packets coming in on gw_interface jump to CHAIN_TO_ROUTER */
	rc |= iptables_do_command("-t filter -I INPUT -i %s -s %s -j "+CHAIN_TO_ROUTER, gw_interface, gw_iprange)
	/* CHAIN_TO_ROUTER packets marked BLOCKED  DROP */
	rc |= iptables_do_command("-t filter -A "+CHAIN_TO_ROUTER+" -m mark --mark 0x%x%s -j DROP", FW_MARK_BLOCKED, markmask)
	/* CHAIN_TO_ROUTER, invalid packets  DROP */
	rc |= iptables_do_command("-t filter -A " + CHAIN_TO_ROUTER + " -m conntrack --ctstate INVALID -j DROP")
	/* CHAIN_TO_ROUTER, related and established packets  ACCEPT */
	rc |= iptables_do_command("-t filter -A " + CHAIN_TO_ROUTER + " -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT")
	/* CHAIN_TO_ROUTER, bogus SYN packets  DROP */
	rc |= iptables_do_command("-t filter -A " + CHAIN_TO_ROUTER + " -p tcp --tcp-flags SYN SYN \\! --tcp-option 2 -j  DROP")

	/* CHAIN_TO_ROUTER, packets to HTTP listening on gw_port on router ACCEPT */
	rc |= iptables_do_command("-t filter -A "+CHAIN_TO_ROUTER+" -p tcp --dport %d -j ACCEPT", gw_port)
	/* CHAIN_TO_ROUTER, packets to HTTPS listening on gw_port_ssl on router ACCEPT */
	rc |= iptables_do_command("-t filter -A "+CHAIN_TO_ROUTER+" -p tcp --dport %d -j ACCEPT", gw_port_ssl)

	/////////////////
	/* CHAIN_TO_ROUTER, packets marked TRUSTED: */

	/* if trusted-users-to-router ruleset is empty:
	 *    use empty ruleset policy
	 * else:
	 *    jump to CHAIN_TRUSTED_TO_ROUTER, and load and use users-to-router ruleset
	 */
	if is_empty_ruleset("trusted-users-to-router") {
		// TODO: Implement
		rc |= iptables_do_command("-t filter -A "+CHAIN_TO_ROUTER+" -m mark --mark 0x%x%s -j %s", FW_MARK_TRUSTED, markmask, get_empty_ruleset_policy("trusted-users-to-router"))
	} else {
		rc |= iptables_do_command("-t filter -A "+CHAIN_TO_ROUTER+" -m mark --mark 0x%x%s -j "+CHAIN_TRUSTED_TO_ROUTER, FW_MARK_TRUSTED, markmask)
		/* CHAIN_TRUSTED_TO_ROUTER, related and established packets  ACCEPT */
		rc |= iptables_do_command("-t filter -A " + CHAIN_TRUSTED_TO_ROUTER + " -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT")
		/* CHAIN_TRUSTED_TO_ROUTER, append the "trusted-users-to-router" ruleset */
		rc |= _iptables_append_ruleset("filter", "trusted-users-to-router", CHAIN_TRUSTED_TO_ROUTER)
		/* CHAIN_TRUSTED_TO_ROUTER, any packets not matching that ruleset  REJECT */
		rc |= iptables_do_command("-t filter -A " + CHAIN_TRUSTED_TO_ROUTER + " -j REJECT --reject-with icmp-port-unreachable")
	}

	/* CHAIN_TO_ROUTER, other packets: */

	/* if users-to-router ruleset is empty:
	 *    use empty ruleset policy
	 * else:
	 *    load and use users-to-router ruleset
	 */
	if is_empty_ruleset("users-to-router") {
		// TODO: Implement
		rc |= iptables_do_command("-t filter -A "+CHAIN_TO_ROUTER+" -j %s", get_empty_ruleset_policy("users-to-router"))
	} else {
		/* CHAIN_TO_ROUTER, append the "users-to-router" ruleset */
		rc |= _iptables_append_ruleset("filter", "users-to-router", CHAIN_TO_ROUTER)
		/* everything else, REJECT */
		rc |= iptables_do_command("-t filter -A " + CHAIN_TO_ROUTER + " -j REJECT --reject-with icmp-port-unreachable")

	}

	/*
	 * filter FORWARD chain
	 */

	/* packets coming in on gw_interface jump to CHAIN_TO_INTERNET */
	rc |= iptables_do_command("-t filter -I FORWARD -i %s -s %s -j "+CHAIN_TO_INTERNET, gw_interface, gw_iprange)
	/* CHAIN_TO_INTERNET packets marked BLOCKED  DROP */
	rc |= iptables_do_command("-t filter -A "+CHAIN_TO_INTERNET+" -m mark --mark 0x%x%s -j DROP", FW_MARK_BLOCKED, markmask)
	/* CHAIN_TO_INTERNET, invalid packets  DROP */
	rc |= iptables_do_command("-t filter -A " + CHAIN_TO_INTERNET + " -m conntrack --ctstate INVALID -j DROP")
	/* CHAIN_TO_INTERNET, deal with MSS */
	if set_mss {
		/* XXX this mangles, so 'should' be done in the mangle POSTROUTING chain.
		 * However OpenWRT standard S35firewall does it in filter FORWARD,
		 * and since we are pre-empting that chain here, we put it in */
		if mss_value > 0 { /* set specific MSS value */
			rc |= iptables_do_command("-t filter -A "+CHAIN_TO_INTERNET+" -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --set-mss %d", mss_value)
		} else { /* allow MSS as large as possible */
			rc |= iptables_do_command("-t filter -A " + CHAIN_TO_INTERNET + " -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu")
		}
	}

	/* CHAIN_TO_INTERNET, packets marked TRUSTED: */

	/* if trusted-users ruleset is empty:
	 *    use empty ruleset policy
	 * else:
	 *    jump to CHAIN_TRUSTED, and load and use trusted-users ruleset
	 */
	if is_empty_ruleset("trusted-users") {
		// TODO: Implement
		rc |= iptables_do_command("-t filter -A "+CHAIN_TO_INTERNET+" -m mark --mark 0x%x%s -j %s", FW_MARK_TRUSTED, markmask, get_empty_ruleset_policy("trusted-users"))
	} else {
		rc |= iptables_do_command("-t filter -A "+CHAIN_TO_INTERNET+" -m mark --mark 0x%x%s -j "+CHAIN_TRUSTED, FW_MARK_TRUSTED, markmask)
		/* CHAIN_TRUSTED, related and established packets  ACCEPT */
		rc |= iptables_do_command("-t filter -A " + CHAIN_TRUSTED + " -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT")
		/* CHAIN_TRUSTED, append the "trusted-users" ruleset */
		rc |= _iptables_append_ruleset("filter", "trusted-users", CHAIN_TRUSTED)
		/* CHAIN_TRUSTED, any packets not matching that ruleset  REJECT */
		rc |= iptables_do_command("-t filter -A " + CHAIN_TRUSTED + " -j REJECT --reject-with icmp-port-unreachable")
	}

	/* CHAIN_TO_INTERNET, packets marked AUTHENTICATED: */

	/* if authenticated-users ruleset is empty:
	 *    use empty ruleset policy
	 * else:
	 *    jump to CHAIN_AUTHENTICATED, and load and use authenticated-users ruleset
	 */
	if is_empty_ruleset("authenticated-users") {
		// TODO: Implement
		rc |= iptables_do_command("-t filter -A "+CHAIN_TO_INTERNET+" -m mark --mark 0x%x%s -j %s", FW_MARK_AUTHENTICATED, markmask, get_empty_ruleset_policy("authenticated-users"))
	} else {
		rc |= iptables_do_command("-t filter -A "+CHAIN_TO_INTERNET+" -m mark --mark 0x%x%s -j "+CHAIN_AUTHENTICATED, FW_MARK_AUTHENTICATED, markmask)
		/* CHAIN_AUTHENTICATED, related and established packets  ACCEPT */
		rc |= iptables_do_command("-t filter -A " + CHAIN_AUTHENTICATED + " -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT")
		/* CHAIN_AUTHENTICATED, append the "authenticated-users" ruleset */
		rc |= _iptables_append_ruleset("filter", "authenticated-users", CHAIN_AUTHENTICATED)
		/* CHAIN_AUTHENTICATED, any packets not matching that ruleset  REJECT */
		rc |= iptables_do_command("-t filter -A " + CHAIN_AUTHENTICATED + " -j REJECT --reject-with icmp-port-unreachable")
	}

	/* CHAIN_TO_INTERNET, other packets: */

	/* if preauthenticated-users ruleset is empty:
	 *    use empty ruleset policy
	 * else:
	 *    load and use authenticated-users ruleset
	 */
	if is_empty_ruleset("preauthenticated-users") {
		// TODO: Implement
		rc |= iptables_do_command("-t filter -A "+CHAIN_TO_INTERNET+" -j %s ", get_empty_ruleset_policy("preauthenticated-users"))
	} else {
		rc |= _iptables_append_ruleset("filter", "preauthenticated-users", CHAIN_TO_INTERNET)
	}
	/* CHAIN_TO_INTERNET, all other packets REJECT */
	rc |= iptables_do_command("-t filter -A " + CHAIN_TO_INTERNET + " -j REJECT --reject-with icmp-port-unreachable")

	/*
	 * End of filter table chains and rules
	 **************************************
	 */
}

func iptables_fw_destroy() {
	fmt.Printf("Destroying iptables entries\n")

	/*
	 *
	 * Everything in the mangle table
	 *
	 */
	fmt.Printf("Destroying chains in the MANGLE table\n")
	iptables_fw_destroy_mention("mangle", "PREROUTING", CHAIN_TRUSTED)
	iptables_fw_destroy_mention("mangle", "PREROUTING", CHAIN_BLOCKED)
	iptables_fw_destroy_mention("mangle", "PREROUTING", CHAIN_ALLOWED)
	iptables_fw_destroy_mention("mangle", "PREROUTING", CHAIN_OUTGOING)
	iptables_fw_destroy_mention("mangle", "POSTROUTING", CHAIN_INCOMING)
	iptables_do_command("-t mangle -F " + CHAIN_TRUSTED)
	iptables_do_command("-t mangle -F " + CHAIN_BLOCKED)
	iptables_do_command("-t mangle -F " + CHAIN_ALLOWED)
	iptables_do_command("-t mangle -F " + CHAIN_OUTGOING)
	iptables_do_command("-t mangle -F " + CHAIN_INCOMING)
	iptables_do_command("-t mangle -X " + CHAIN_TRUSTED)
	iptables_do_command("-t mangle -X " + CHAIN_BLOCKED)
	iptables_do_command("-t mangle -X " + CHAIN_ALLOWED)
	iptables_do_command("-t mangle -X " + CHAIN_OUTGOING)
	iptables_do_command("-t mangle -X " + CHAIN_INCOMING)

	/*
	 *
	 * Everything in the nat table
	 *
	 */

	fmt.Printf("Destroying chains in the NAT table\n")
	iptables_fw_destroy_mention("nat", "PREROUTING", CHAIN_OUTGOING)
	iptables_do_command("-t nat -F " + CHAIN_OUTGOING)
	iptables_do_command("-t nat -X " + CHAIN_OUTGOING)

	/*
	 *
	 * Everything in the filter table
	 *
	 */

	fmt.Printf("Destroying chains in the FILTER table\n")
	iptables_fw_destroy_mention("filter", "INPUT", CHAIN_TO_ROUTER)
	iptables_fw_destroy_mention("filter", "FORWARD", CHAIN_TO_INTERNET)
	iptables_do_command("-t filter -F " + CHAIN_TO_ROUTER)
	iptables_do_command("-t filter -F " + CHAIN_TO_INTERNET)
	iptables_do_command("-t filter -F " + CHAIN_AUTHENTICATED)
	iptables_do_command("-t filter -F " + CHAIN_TRUSTED)
	iptables_do_command("-t filter -F " + CHAIN_TRUSTED_TO_ROUTER)
	iptables_do_command("-t filter -X " + CHAIN_TO_ROUTER)
	iptables_do_command("-t filter -X " + CHAIN_TO_INTERNET)
	iptables_do_command("-t filter -X " + CHAIN_AUTHENTICATED)
	iptables_do_command("-t filter -X " + CHAIN_TRUSTED)
	iptables_do_command("-t filter -X " + CHAIN_TRUSTED_TO_ROUTER)
}

func iptables_fw_destroy_mention(table string, chain string, mention string) bool {
	cmd := fmt.Sprintf("iptables -t %v -L %v -n --line-numbers -v", table, chain)
	out, err := exec.Command("sh", "-c", cmd).Output()
	if err != nil {
		fmt.Printf("exec.Command error: %v, cmd: %v\n", err, cmd)
		return false
	}
	s := string(out[:])
	r := bufio.NewReader(strings.NewReader(s))
	// Skip first two lines
	r.ReadLine()
	r.ReadLine()

	found := false
	line, err := r.ReadString('\n')
	for err == nil {
		if strings.Contains(line, mention) {
			// Found mention - Get the rule number into rulenum.
			rulenum := 0
			read, err := fmt.Sscanf(line, "%9[0-9]", &rulenum)
			if read == 1 && err == nil {
				fmt.Printf("Deleting rule %v from %v.%v because it mentions %v",
					rulenum, table, chain, mention)
				cmd2 := fmt.Sprintf("-t %v -D %v %v", table, chain, rulenum)
				iptables_do_command(cmd2)
				found = true
				break
			}
		}
		line, err = r.ReadString('\n')
	}

	if found {
		iptables_fw_destroy_mention(table, chain, mention)
	}
	return found
}

type Client struct {
	ip  string
	mac string
	idx int
}

const (
	AuthAction_Auth int = iota
	AuthAction_Deauth
)

func iptables_fw_access(client Client) int {
	log.Printf("Authenticating %v %v %v\n", client.ip, client.mac, client.idx)
	rc := 0
	/* This rule is for marking upload (outgoing) packets, and for upload byte counting */
	rc |= iptables_do_command("-t mangle -A "+CHAIN_OUTGOING+" -s %s -m mac --mac-source %s -j MARK %s 0x%x%x", client.ip, client.mac, markop, client.idx+10, FW_MARK_AUTHENTICATED)
	rc |= iptables_do_command("-t mangle -A "+CHAIN_INCOMING+" -d %s -j MARK %s 0x%x%x", client.ip, markop, client.idx+10, FW_MARK_AUTHENTICATED)

	/* This rule is just for download (incoming) byte counting, see iptables_fw_counters_update() */
	rc |= iptables_do_command("-t mangle -A "+CHAIN_INCOMING+" -d %s -j ACCEPT", client.ip)
	return rc
}

type HelloHandler struct{}

func (h HelloHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html")
	w.Write([]byte("Hello, world<br>\n"))
	w.Write([]byte(fmt.Sprintf("%v", time.Now())))
}

type RedirectHandler struct{}

func (h RedirectHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path == "/cert" {
		w.Header().Set("Content-Type", "application/x-pem-file; charset=utf-8")
		w.Header().Set("Content-Disposition", "attachment; filename=\"cert.pem\"")
		http.ServeFile(w, r, "ssl/cert.pem")
	} else {
		http.Redirect(w, r, "https://192.168.24.1:2051/", 301)
		w.Header().Set("Content-Type", "text/html")
		w.Write([]byte("Redirected<br>\n"))
		w.Write([]byte(fmt.Sprintf("%v", time.Now())))
	}
}

func DownloadCertAction(w http.ResponseWriter, r *http.Request) {
	http.ServeFile(w, r, "ssl/cert.pem")
}

func AuthAction(w http.ResponseWriter, req *http.Request) {
	w.Header().Set("Content-Type", "text/html")
	w.Write([]byte(fmt.Sprintf("%v\n", time.Now())))

	// req.RemoteAddr is in the form of ip:port. Trim the port.
	client_ip := req.RemoteAddr[:strings.LastIndex(req.RemoteAddr, ":")]
	client_mac := arp_get(client_ip)
	client_idx := 1
	if iptables_fw_access(Client{client_ip, client_mac, client_idx}) == 0 {
		w.Write([]byte(fmt.Sprintf("Authenticated %v\n", client_ip)))
		return
	}
	w.Write([]byte(fmt.Sprintf("NOT Authenticated %v\n", client_ip)))
}

func FileExists(path string) bool {
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		return true
	}
	return false
}

func RunHttpsServer() {
	cfg := &tls.Config{}
	cert, err := tls.LoadX509KeyPair("ssl/cert.pem", "ssl/key_decrypted.pem")
	if err != nil {
		log.Fatal(err)
	}
	cfg.Certificates = append(cfg.Certificates, cert)
	cfg.BuildNameToCertificate()

	https_server := http.Server{
		Addr:      ":2051",
		Handler:   HelloHandler{},
		TLSConfig: cfg,
	}
	err = https_server.ListenAndServeTLS("", "")
	if err != nil {
		fmt.Printf("Could not start HTTPS server: %v\n", err)
	}
}

func main() {
	go func() {
		sigchan := make(chan os.Signal, 1)
		signal.Notify(sigchan, os.Interrupt)
		<-sigchan
		iptables_fw_destroy()
		os.Exit(0)
	}()

	iptables_init()
	log.Println("Initialized iptables rules")

	//http.HandleFunc("/auth", AuthAction)
	http.HandleFunc("/cert", DownloadCertAction)

	run_https := true
	if !FileExists("ssl/cert.pem") {
		log.Println("ssl/cert.pem doesn't exist, not running HTTPS server")
		run_https = false
	}
	if !FileExists("ssl/key.pem") {
		log.Println("ssl/key.pem doesn't exist, not running HTTPS server")
		run_https = false
	}

	if run_https {
		log.Println("Starting HTTPS server at port 2051")
		go RunHttpsServer()
	}

	log.Println("Starting HTTP server at port 2050")
	server := http.Server{
		Addr:    ":2050",
		Handler: RedirectHandler{},
	}
	err := server.ListenAndServe()
	if err != nil {
		fmt.Printf("Could not start HTTP server: %v\n", err)
		return
	}
	log.Println("Started")
}
