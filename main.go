package main

import (
	"bufio"
	"bytes"
	"crypto/tls"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"os/signal"
	"strings"
	"sync"
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

	config Config
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

type Client struct {
	ip        string
	mac       string
	idx       int
	auth_time time.Time
}

var clients map[string]Client
var clients_mutex *sync.Mutex

const (
	AuthAction_None int = iota
	AuthAction_Auth
	AuthAction_Deauth
)

// Configuration
const (
	gw_interface = "wlan0"
	gw_iprange   = "0.0.0.0/0"
	gw_address   = "192.168.24.1"
	gw_port      = 80
	gw_port_ssl  = 443
)

func _iptables_init_marks() {
	FW_MARK_PREAUTHENTICATED = 0
	FW_MARK_BLOCKED = 0x100
	FW_MARK_TRUSTED = 0x200
	FW_MARK_AUTHENTICATED = 0x400
	FW_MARK_MASK = FW_MARK_BLOCKED | FW_MARK_TRUSTED | FW_MARK_AUTHENTICATED
}

func iptables_do_command(format string, a ...interface{}) int {
	var errbuf bytes.Buffer
	args_str := fmt.Sprintf(format, a...)
	args := strings.Split(args_str, " ")
	args = append([]string{"--wait"}, args...)
	cmd := exec.Command("/sbin/iptables", args...)
	cmd.Stderr = &errbuf
	err := cmd.Run()
	if err != nil {
		cmd_str := "/sbin/iptables " + strings.Join(args, " ")
		fmt.Printf("Command: %v\n", cmd_str)
		fmt.Printf("Error: %v, %v\n", err, errbuf.String())
		return 1
	}
	return 0
}

func iptables_do_command_or_die(format string, a ...interface{}) int {
	rc := iptables_do_command(format, a...)
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
		log.Printf("Kernel supports --or-mark.\n")
		markop = "--or-mark"
	} else {
		log.Printf("Kernel does not support iptables --or-mark.  Using --set-mark instead.\n")
		markop = "--set-mark"
	}

	/* See if kernel supports mark masking */
	if 0 == iptables_do_command("-t filter -I FORWARD 1 -m mark --mark 0x%x/0x%x -j REJECT", FW_MARK_BLOCKED, FW_MARK_MASK) {
		iptables_do_command("-t filter -D FORWARD 1") /* delete test rule we just inserted */
		log.Printf("Kernel supports mark masking.\n")
		markmask = fmt.Sprintf("/0x%x", FW_MARK_MASK)
	} else {
		log.Printf("Kernel does not support iptables mark masking.  Using empty mask.\n")
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
		command += fmt.Sprintf("-d %s ", rule.mask)
	}
	if rule.protocol != "" {
		command += fmt.Sprintf("-p %s ", rule.protocol)
	}
	if rule.port != "" {
		command += fmt.Sprintf("--dport %s ", rule.port)
	}
	if rule.ipset != "" {
		command += fmt.Sprintf("-m set --match-set %s dst ", rule.ipset)
	}
	command += fmt.Sprintf("-j %s", mode)
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
			FirewallRule{TARGET_REJECT, "" /* protocol */, "" /* port */, "192.168.0.0/16" /* mask */, "" /* ipset */},
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
		log.Printf("Loading rule \"%s\" into table %s, chain %s\n", cmd, table, chain)
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
	set_mss := true
	mss_value := 0
	rc := 0

	FirewallInit()

	/////////////////////////////////////
	// Enable internet sharing:
	iptables_do_command_or_die("-t nat -I POSTROUTING -o eth0 -j MASQUERADE")
	iptables_do_command_or_die("-I FORWARD -i eth0 -o wlan0 -m state --state RELATED,ESTABLISHED -j ACCEPT")
	iptables_do_command_or_die("-I FORWARD -i wlan0 -o eth0 -j ACCEPT")

	////////////////////////////////////
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
	iptables_do_command("-t nat -N " + CHAIN_OUTGOING)

	/* packets coming in on gw_interface jump to CHAIN_OUTGOING */
	iptables_do_command_or_die("-t nat -I PREROUTING -i %s -s %s -j "+CHAIN_OUTGOING, gw_interface, gw_iprange)
	/* CHAIN_OUTGOING, packets marked TRUSTED  ACCEPT */
	iptables_do_command_or_die("-t nat -A "+CHAIN_OUTGOING+" -m mark --mark 0x%x%s -j ACCEPT", FW_MARK_TRUSTED, markmask)
	/* CHAIN_OUTGOING, packets marked AUTHENTICATED  ACCEPT */
	iptables_do_command_or_die("-t nat -A "+CHAIN_OUTGOING+" -m mark --mark 0x%x%s -j ACCEPT", FW_MARK_AUTHENTICATED, markmask)
	/* CHAIN_OUTGOING, append the "preauthenticated-users" ruleset */
	_iptables_append_ruleset("nat", "preauthenticated-users", CHAIN_OUTGOING)

	/* CHAIN_OUTGOING, packets for tcp port 80, redirect to gw_port on primary address for the iface */
	iptables_do_command_or_die("-t nat -A "+CHAIN_OUTGOING+" -p tcp --dport 80 -j DNAT --to-destination %s:%d", gw_address, gw_port)
	/* CHAIN_OUTGOING, packets for tcp port 443, redirect to gw_port_ssl on primary address for the iface */
	iptables_do_command_or_die("-t nat -A "+CHAIN_OUTGOING+" -p tcp --dport 443 -j DNAT --to-destination %s:%d", gw_address, gw_port_ssl)

	/* CHAIN_OUTGOING, other packets  ACCEPT */
	iptables_do_command_or_die("-t nat -A " + CHAIN_OUTGOING + " -j ACCEPT")

	// * End of nat table chains and rules.

	// Set up filter table chains and rules.
	/* Create new chains in the filter table */
	iptables_do_command_or_die("-t filter -N " + CHAIN_TO_INTERNET)
	iptables_do_command_or_die("-t filter -N " + CHAIN_TO_ROUTER)
	iptables_do_command_or_die("-t filter -N " + CHAIN_AUTHENTICATED)
	iptables_do_command_or_die("-t filter -N " + CHAIN_TRUSTED)
	iptables_do_command_or_die("-t filter -N " + CHAIN_TRUSTED_TO_ROUTER)

	/*
	 * filter INPUT chain
	 */
	/* packets coming in on gw_interface jump to CHAIN_TO_ROUTER */
	iptables_do_command_or_die("-t filter -I INPUT -i %s -s %s -j "+CHAIN_TO_ROUTER, gw_interface, gw_iprange)
	/* CHAIN_TO_ROUTER packets marked BLOCKED  DROP */
	iptables_do_command_or_die("-t filter -A "+CHAIN_TO_ROUTER+" -m mark --mark 0x%x%s -j DROP", FW_MARK_BLOCKED, markmask)
	/* CHAIN_TO_ROUTER, invalid packets  DROP */
	iptables_do_command_or_die("-t filter -A " + CHAIN_TO_ROUTER + " -m conntrack --ctstate INVALID -j DROP")
	/* CHAIN_TO_ROUTER, related and established packets  ACCEPT */
	iptables_do_command_or_die("-t filter -A " + CHAIN_TO_ROUTER + " -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT")
	/* CHAIN_TO_ROUTER, bogus SYN packets  DROP */
	// NOTE: Not escaping ! here.
	iptables_do_command_or_die("-t filter -A " + CHAIN_TO_ROUTER + " -p tcp --tcp-flags SYN SYN ! --tcp-option 2 -j DROP")

	/* CHAIN_TO_ROUTER, packets to HTTP listening on gw_port on router ACCEPT */
	iptables_do_command_or_die("-t filter -A "+CHAIN_TO_ROUTER+" -p tcp --dport %d -j ACCEPT", gw_port)
	/* CHAIN_TO_ROUTER, packets to HTTPS listening on gw_port_ssl on router ACCEPT */
	iptables_do_command_or_die("-t filter -A "+CHAIN_TO_ROUTER+" -p tcp --dport %d -j ACCEPT", gw_port_ssl)

	/////////////////
	/* CHAIN_TO_ROUTER, packets marked TRUSTED: */

	/* if trusted-users-to-router ruleset is empty:
	 *    use empty ruleset policy
	 * else:
	 *    jump to CHAIN_TRUSTED_TO_ROUTER, and load and use users-to-router ruleset
	 */
	if is_empty_ruleset("trusted-users-to-router") {
		// TODO: Implement
		iptables_do_command_or_die("-t filter -A "+CHAIN_TO_ROUTER+" -m mark --mark 0x%x%s -j %s", FW_MARK_TRUSTED, markmask, get_empty_ruleset_policy("trusted-users-to-router"))
	} else {
		iptables_do_command_or_die("-t filter -A "+CHAIN_TO_ROUTER+" -m mark --mark 0x%x%s -j "+CHAIN_TRUSTED_TO_ROUTER, FW_MARK_TRUSTED, markmask)
		/* CHAIN_TRUSTED_TO_ROUTER, related and established packets  ACCEPT */
		iptables_do_command_or_die("-t filter -A " + CHAIN_TRUSTED_TO_ROUTER + " -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT")
		/* CHAIN_TRUSTED_TO_ROUTER, append the "trusted-users-to-router" ruleset */
		rc |= _iptables_append_ruleset("filter", "trusted-users-to-router", CHAIN_TRUSTED_TO_ROUTER)
		/* CHAIN_TRUSTED_TO_ROUTER, any packets not matching that ruleset  REJECT */
		iptables_do_command_or_die("-t filter -A " + CHAIN_TRUSTED_TO_ROUTER + " -j REJECT --reject-with icmp-port-unreachable")
	}

	/* CHAIN_TO_ROUTER, other packets: */

	/* if users-to-router ruleset is empty:
	 *    use empty ruleset policy
	 * else:
	 *    load and use users-to-router ruleset
	 */
	if is_empty_ruleset("users-to-router") {
		// TODO: Implement
		iptables_do_command_or_die("-t filter -A "+CHAIN_TO_ROUTER+" -j %s", get_empty_ruleset_policy("users-to-router"))
	} else {
		/* CHAIN_TO_ROUTER, append the "users-to-router" ruleset */
		rc |= _iptables_append_ruleset("filter", "users-to-router", CHAIN_TO_ROUTER)
		/* everything else, REJECT */
		iptables_do_command_or_die("-t filter -A " + CHAIN_TO_ROUTER + " -j REJECT --reject-with icmp-port-unreachable")
	}

	/*
	 * filter FORWARD chain
	 */

	/* packets coming in on gw_interface jump to CHAIN_TO_INTERNET */
	iptables_do_command_or_die("-t filter -I FORWARD -i %s -s %s -j "+CHAIN_TO_INTERNET, gw_interface, gw_iprange)
	/* CHAIN_TO_INTERNET packets marked BLOCKED  DROP */
	iptables_do_command_or_die("-t filter -A "+CHAIN_TO_INTERNET+" -m mark --mark 0x%x%s -j DROP", FW_MARK_BLOCKED, markmask)
	/* CHAIN_TO_INTERNET, invalid packets  DROP */
	iptables_do_command_or_die("-t filter -A " + CHAIN_TO_INTERNET + " -m conntrack --ctstate INVALID -j DROP")
	/* CHAIN_TO_INTERNET, deal with MSS */
	if set_mss {
		/* XXX this mangles, so 'should' be done in the mangle POSTROUTING chain.
		 * However OpenWRT standard S35firewall does it in filter FORWARD,
		 * and since we are pre-empting that chain here, we put it in */
		if mss_value > 0 { /* set specific MSS value */
			iptables_do_command_or_die("-t filter -A "+CHAIN_TO_INTERNET+" -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --set-mss %d", mss_value)
		} else { /* allow MSS as large as possible */
			iptables_do_command_or_die("-t filter -A " + CHAIN_TO_INTERNET + " -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu")
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
		iptables_do_command_or_die("-t filter -A "+CHAIN_TO_INTERNET+" -m mark --mark 0x%x%s -j %s", FW_MARK_TRUSTED, markmask, get_empty_ruleset_policy("trusted-users"))
	} else {
		iptables_do_command_or_die("-t filter -A "+CHAIN_TO_INTERNET+" -m mark --mark 0x%x%s -j "+CHAIN_TRUSTED, FW_MARK_TRUSTED, markmask)
		/* CHAIN_TRUSTED, related and established packets  ACCEPT */
		iptables_do_command_or_die("-t filter -A " + CHAIN_TRUSTED + " -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT")
		/* CHAIN_TRUSTED, append the "trusted-users" ruleset */
		rc |= _iptables_append_ruleset("filter", "trusted-users", CHAIN_TRUSTED)
		/* CHAIN_TRUSTED, any packets not matching that ruleset  REJECT */
		iptables_do_command_or_die("-t filter -A " + CHAIN_TRUSTED + " -j REJECT --reject-with icmp-port-unreachable")
	}

	/* CHAIN_TO_INTERNET, packets marked AUTHENTICATED: */

	/* if authenticated-users ruleset is empty:
	 *    use empty ruleset policy
	 * else:
	 *    jump to CHAIN_AUTHENTICATED, and load and use authenticated-users ruleset
	 */
	if is_empty_ruleset("authenticated-users") {
		// TODO: Implement
		iptables_do_command_or_die("-t filter -A "+CHAIN_TO_INTERNET+" -m mark --mark 0x%x%s -j %s", FW_MARK_AUTHENTICATED, markmask, get_empty_ruleset_policy("authenticated-users"))
	} else {
		iptables_do_command_or_die("-t filter -A "+CHAIN_TO_INTERNET+" -m mark --mark 0x%x%s -j "+CHAIN_AUTHENTICATED, FW_MARK_AUTHENTICATED, markmask)
		/* CHAIN_AUTHENTICATED, related and established packets  ACCEPT */
		iptables_do_command_or_die("-t filter -A " + CHAIN_AUTHENTICATED + " -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT")
		/* CHAIN_AUTHENTICATED, append the "authenticated-users" ruleset */
		rc |= _iptables_append_ruleset("filter", "authenticated-users", CHAIN_AUTHENTICATED)
		/* CHAIN_AUTHENTICATED, any packets not matching that ruleset  REJECT */
		iptables_do_command_or_die("-t filter -A " + CHAIN_AUTHENTICATED + " -j REJECT --reject-with icmp-port-unreachable")
	}

	/* CHAIN_TO_INTERNET, other packets: */

	/* if preauthenticated-users ruleset is empty:
	 *    use empty ruleset policy
	 * else:
	 *    load and use authenticated-users ruleset
	 */
	if is_empty_ruleset("preauthenticated-users") {
		// TODO: Implement
		iptables_do_command_or_die("-t filter -A "+CHAIN_TO_INTERNET+" -j %s ", get_empty_ruleset_policy("preauthenticated-users"))
	} else {
		rc |= _iptables_append_ruleset("filter", "preauthenticated-users", CHAIN_TO_INTERNET)
	}
	/* CHAIN_TO_INTERNET, all other packets REJECT */
	iptables_do_command_or_die("-t filter -A " + CHAIN_TO_INTERNET + " -j REJECT --reject-with icmp-port-unreachable")

	/*
	 * End of filter table chains and rules
	 **************************************
	 */
}

func iptables_fw_destroy() {
	fmt.Fprintln(os.Stderr, "Destroying iptables entries")

	// Delete wlan0 to eth0 bridge:
	iptables_do_command("-t nat -D POSTROUTING -o eth0 -j MASQUERADE")
	iptables_do_command("-D FORWARD -i eth0 -o wlan0 -m state --state RELATED,ESTABLISHED -j ACCEPT")
	iptables_do_command("-D FORWARD -i wlan0 -o eth0 -j ACCEPT")

	/*
	 *
	 * Everything in the mangle table
	 *
	 */
	fmt.Fprintln(os.Stderr, "Destroying chains in the MANGLE table")
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

	fmt.Fprintln(os.Stderr, "Destroying chains in the NAT table")
	iptables_fw_destroy_mention("nat", "PREROUTING", CHAIN_OUTGOING)
	iptables_do_command("-t nat -F " + CHAIN_OUTGOING)
	iptables_do_command("-t nat -X " + CHAIN_OUTGOING)

	/*
	 *
	 * Everything in the filter table
	 *
	 */

	fmt.Fprintln(os.Stderr, "Destroying chains in the FILTER table")
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
	fmt.Fprintln(os.Stderr, "Destroying iptables entries DONE")
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
	return iptables_fw_destroy_mention_with_reader(table, chain, mention, r)
}

func iptables_fw_destroy_mention_with_reader(table string, chain string, mention string, r *bufio.Reader) bool {
	// Skip first two lines
	r.ReadLine()
	r.ReadLine()

	found := false
	line, err := r.ReadString('\n')
	for err == nil {
		if strings.Contains(line, mention) {
			// Found mention - Get the rule number into rulenum.
			rulenum := 0
			read, err := fmt.Sscanf(line, "%d", &rulenum)
			if read == 1 && err == nil {
				log.Printf("Deleting rule %v from %v.%v because it mentions %v\n",
					rulenum, table, chain, mention)
				cmd2 := fmt.Sprintf("-t %v -D %v %v", table, chain, rulenum)
				iptables_do_command_or_die(cmd2)
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

func iptables_fw_access(client Client, auth_action int) int {
	rc := 0
	if auth_action == AuthAction_Auth {
		log.Printf("Authenticating %v %v %v\n", client.ip, client.mac, client.idx)
		/* This rule is for marking upload (outgoing) packets, and for upload byte counting */
		rc |= iptables_do_command("-t mangle -A "+CHAIN_OUTGOING+" -s %s -m mac --mac-source %s -j MARK %s 0x%x%x", client.ip, client.mac, markop, client.idx+10, FW_MARK_AUTHENTICATED)
		rc |= iptables_do_command("-t mangle -A "+CHAIN_INCOMING+" -d %s -j MARK %s 0x%x%x", client.ip, markop, client.idx+10, FW_MARK_AUTHENTICATED)

		/* This rule is just for download (incoming) byte counting, see iptables_fw_counters_update() */
		rc |= iptables_do_command("-t mangle -A "+CHAIN_INCOMING+" -d %s -j ACCEPT", client.ip)

		if rc == 0 {
			clients_mutex.Lock()
			client.auth_time = time.Now()
			clients[client.mac] = client
			clients_mutex.Unlock()
		}
		return rc
	}

	if auth_action == AuthAction_Deauth {
		log.Printf("De-authenticating %v %v %v\n", client.ip, client.mac, client.idx)
		/* Remove the authentication rules. */
		rc |= iptables_do_command("-t mangle -D "+CHAIN_OUTGOING+" -s %s -m mac --mac-source %s -j MARK %s 0x%x%x", client.ip, client.mac, markop, client.idx+10, FW_MARK_AUTHENTICATED)
		rc |= iptables_do_command("-t mangle -D "+CHAIN_INCOMING+" -d %s -j MARK %s 0x%x%x", client.ip, markop, client.idx+10, FW_MARK_AUTHENTICATED)
		rc |= iptables_do_command("-t mangle -D "+CHAIN_INCOMING+" -d %s -j ACCEPT", client.ip)

		if rc == 0 {
			clients_mutex.Lock()
			client.auth_time = time.Time{}
			clients[client.mac] = client
			clients_mutex.Unlock()
		}
		return rc
	}

	panic(fmt.Sprintf("Incorrect auth action: %d", auth_action))
	return -1
}

func DisableCaching(w http.ResponseWriter) {
	w.Header().Set("Cache-Control", "no-cache, no-store, must-revalidate")
	w.Header().Set("Pragma", "no-cache")
	w.Header().Set("Expires", "0")
}

type HomePageHandler struct {
	redirect_http_to_https bool
	redirect_to_gateway    bool
	gateway_hostname       string
	gateway_title          string
}

func GetHostname(hostname string, port int) string {
	if port == 80 || port == 443 {
		return hostname
	}
	return fmt.Sprintf("%v:%v", hostname, port)
}

func (h HomePageHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	DisableCaching(w)

	redirect_hostname := GetHostname(gw_address, gw_port)
	// If a hostname is provided, use it instead of the IP address of the gateway
	// when redirecting.
	if len(h.gateway_hostname) > 0 {
		redirect_hostname = GetHostname(h.gateway_hostname, gw_port)
	}
	if h.redirect_http_to_https && r.TLS == nil {
		redirect_url := fmt.Sprintf("https://%v/", redirect_hostname)
		log.Printf("Redirecting to HTTPS (%v)\n", redirect_url)
		http.Redirect(w, r, redirect_url, 301)
		return
	}
	if h.redirect_to_gateway && r.Host != redirect_hostname {
		// If not already redirected, do the redirect:
		// TODO: Don't assume the original URL is http. These should use r.URL.Scheme
		// instead.
		redirect_url := fmt.Sprintf("http://%v/", redirect_hostname)
		log.Printf("Redirecting to hostname (%v)\n", redirect_url)
		http.Redirect(w, r, redirect_url, 301)
		return
	}

	if r.URL.Path == "/cert.pem" {
		DisableCaching(w)
		w.Header().Set("Content-Type", "application/x-pem-file; charset=utf-8")
		w.Header().Set("Content-Disposition", "attachment; filename=\"cert.pem\"")
		http.ServeFile(w, r, "ssl/cert.pem")
		return
	}

	w.Header().Set("Content-Type", "text/html")
	w.Write([]byte("<html><title>Captive Portal</title>"))
	w.Write([]byte(fmt.Sprintf("<body onunload=''><h3>%v</h3>", h.gateway_title)))

	params, _ := url.ParseQuery(r.URL.RawQuery)
	action := AuthAction_None
	if len(params["action"]) > 0 {
		if params["action"][0] == "login" {
			action = AuthAction_Auth
		} else if params["action"][0] == "logout" {
			action = AuthAction_Deauth
		}
	}

	// r.RemoteAddr is in the form of ip:port. Trim the port.
	client_ip := r.RemoteAddr[:strings.LastIndex(r.RemoteAddr, ":")]
	client_mac := arp_get(client_ip)

	clients_mutex.Lock()
	client, client_found := clients[client_mac]
	if !client_found {
		log.Printf("First time seeing client %v, adding to client list.\n", client_mac)
		client_idx := len(clients) + 1
		client = Client{client_ip, client_mac, client_idx, time.Time{}}
		clients[client_mac] = client
	}
	clients_mutex.Unlock()

	if action == AuthAction_Auth || action == AuthAction_Deauth {
		msg := ""
		if action == AuthAction_Auth {
			log.Printf("Logging in...\n")
			msg = "Login"
		} else {
			log.Printf("Logging out...\n")
			msg = "Logout"
		}
		rc := iptables_fw_access(client, action)
		if rc == 0 {
			// Update client information. Auth time might have changed.
			client = clients[client_mac]
			w.Write([]byte(fmt.Sprintf("<h4>%v successful</h4><br><br>", msg)))
		} else {
			w.Write([]byte(fmt.Sprintf("%v failed, return code: %v<br>", msg, rc)))
		}
	} else {
		log.Printf("No auth action\n")
	}

	clients_mutex.Lock()
	PrintClients()
	clients_mutex.Unlock()

	w.Write([]byte("<a href='?action=login'>LOGIN</a><br><br>\n"))
	w.Write([]byte("<a href='?action=logout'>LOGOUT</a><br><br>\n"))
	w.Write([]byte("In order to view this page without an SSL error, you can <a href='/cert.pem'>download the SSL certificate</a> and install it.<br><br>\n"))
	w.Write([]byte("<pre>"))

	if !client.auth_time.IsZero() {
		w.Write([]byte(fmt.Sprintf("Login time: <b>%v</b><br>", client.auth_time)))
		w.Write([]byte(fmt.Sprintf("Remaining : <b>%v minutes</b><br>",
			1+config.ClientTimeoutInMinutes-int(time.Now().Sub(client.auth_time).Minutes()))))
	} else {
		w.Write([]byte("<b>Not logged in</b><br>"))
	}

	w.Write([]byte(fmt.Sprintf("Client IP : <b>%v</b><br>", client.ip)))
	w.Write([]byte(fmt.Sprintf("Client MAC: <b>%v</b><br>", client.mac)))
	w.Write([]byte(fmt.Sprintf("Client ID : <b>%v</b><br>", client.idx)))

	w.Write([]byte(fmt.Sprintf("Current time: <b>%v</b>", time.Now())))
	w.Write([]byte("</pre>"))
	w.Write([]byte("</body></html>"))
}

func PrintClients() {
	fmt.Printf("=== CLIENT LIST ===\n")
	for _, client := range clients {
		fmt.Printf("Client #%v\n", client.idx)
		fmt.Printf("IP : %s\n", client.ip)
		fmt.Printf("MAC: %s\n", client.mac)
		if !client.auth_time.IsZero() {
			fmt.Printf("Auth Time: %v\n", client.auth_time)
		} else {
			fmt.Printf("Not authenticated\n")
		}
		fmt.Printf("-----------------------\n")
	}
}

func FileExists(path string) bool {
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		return true
	}
	return false
}

func RunHttpsServer(handler HomePageHandler, cert_path string, key_path string) {
	cfg := &tls.Config{}
	cert, err := tls.LoadX509KeyPair(cert_path, key_path)
	if err != nil {
		log.Fatal(err)
	}
	cfg.Certificates = append(cfg.Certificates, cert)
	cfg.BuildNameToCertificate()

	https_server := http.Server{
		Addr:      fmt.Sprintf(":%d", gw_port_ssl),
		Handler:   handler,
		TLSConfig: cfg,
	}
	err = https_server.ListenAndServeTLS("", "")
	if err != nil {
		fmt.Printf("Could not start HTTPS server: %v\n", err)
	}
}

func ClientTimeoutCheck(client_timeout_in_minutes int) {
	for range time.Tick(time.Minute * 1) {
		now := time.Now()
		fmt.Printf("ClientTimeoutCheck at %v\n", now)
		clients_mutex.Lock()
		client_list := clients
		clients_mutex.Unlock()

		for _, client := range client_list {
			if !client.auth_time.IsZero() && int(now.Sub(client.auth_time).Minutes()) > client_timeout_in_minutes {
				log.Printf("Client %v timeout, deauthenticating.\n", client.mac)
				iptables_fw_access(client, AuthAction_Deauth)
			}
		}
	}
}

func main() {
	err := ReadConfig(&config)
	if err != nil {
		fmt.Printf("Could not load configuration: %v\n", err)
		return
	}

	iptables_fw_destroy()
	iptables_init()
	go func() {
		sigchan := make(chan os.Signal, 1)
		signal.Notify(sigchan, os.Interrupt)
		<-sigchan
		iptables_fw_destroy()
		os.Exit(0)
	}()

	clients = make(map[string]Client)
	clients_mutex = &sync.Mutex{}
	log.Println("Initialized iptables rules")

	run_https := true
	if !FileExists(config.SSLCert) {
		log.Printf("SSL certificate %v doesn't exist, not running HTTPS server\n", config.SSLCert)
		run_https = false
	}
	if !FileExists(config.SSLKey) {
		log.Printf("SSL key %v doesn't exist, not running HTTPS server\n", config.SSLKey)
		run_https = false
	}

	go ClientTimeoutCheck(config.ClientTimeoutInMinutes)

	handler := HomePageHandler{redirect_http_to_https: config.RedirectHttpToHttps,
		redirect_to_gateway: config.RedirectToGateway,
		gateway_hostname:    config.GatewayHostname,
		gateway_title:       config.GatewayName,
	}

	if run_https {
		log.Printf("Starting HTTPS server at port %v\n", gw_port_ssl)
		go RunHttpsServer(handler, config.SSLCert, config.SSLKey)
	}

	log.Printf("Starting HTTP server at port %v\n", gw_port)
	server := http.Server{
		Addr:    fmt.Sprintf(":%d", gw_port),
		Handler: handler}
	err = server.ListenAndServe()
	if err != nil {
		fmt.Printf("Could not start HTTP server: %v\n", err)
		return
	}
}
