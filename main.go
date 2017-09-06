package main

import (
	"fmt"
	"log"
	"net/http"
	"os/exec"
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
	FW_MARK_MASK = FW_MARK_BLOCKED | FW_MARK_TRUSTED | FW_MARK_AUTHENTICATED
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

func do_command(cmd string) int {
	out, err := exec.Command("sh", "-c", cmd).Output()
	if err != nil {
		fmt.Printf("IptablesDoCommand error: %v, cmd: %v\n", err, cmd)
		return 1
	}
	if out != nil {
		fmt.Printf("IptablesDoCommand result nonzero, value: %v\n", out)
		return 1
	}
	return 0
}

func iptables_do_command(format string, a ...interface{}) int {
	cmd := fmt.Sprintf(format, a...)
	return do_command("iptables " + cmd)
}

func is_empty_ruleset(ruleset string) bool {
	return true
}

func _iptables_append_ruleset(table string, ruleset string, chain string) int {
	// TODO: Implement
	return 0
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
		//rc |= iptables_do_command("-t filter -A " + CHAIN_TO_ROUTER + " -m mark --mark 0x%x%s -j %s", FW_MARK_TRUSTED, markmask, get_empty_ruleset_policy("trusted-users-to-router"));
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
		//rc |= iptables_do_command("-t filter -A " + CHAIN_TO_ROUTER + " -j %s", get_empty_ruleset_policy("users-to-router"));
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
		//rc |= iptables_do_command("-t filter -A " +CHAIN_TO_INTERNET +" -m mark --mark 0x%x%s -j %s", FW_MARK_TRUSTED, markmask, get_empty_ruleset_policy("trusted-users"));
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
		//rc |= iptables_do_command("-t filter -A " + CHAIN_TO_INTERNET + " -m mark --mark 0x%x%s -j %s", FW_MARK_AUTHENTICATED, markmask, get_empty_ruleset_policy("authenticated-users"));
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
		//rc |= iptables_do_command("-t filter -A "  + CHAIN_TO_INTERNET + " -j %s ",  get_empty_ruleset_policy("preauthenticated-users"));
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

type Client struct {
	ip  string
	mac string
	idx int
}

const (
	AuthAction_Auth int = iota
	AuthAction_Deauth
)

func iptables_fw_access(client Client) {
	log.Println("Authenticating %v %v", client.ip, client.mac)
	rc := 0
	/* This rule is for marking upload (outgoing) packets, and for upload byte counting */
	rc |= iptables_do_command("-t mangle -A "+CHAIN_OUTGOING+" -s %s -m mac --mac-source %s -j MARK %s 0x%x%x", client.ip, client.mac, markop, client.idx+10, FW_MARK_AUTHENTICATED)
	rc |= iptables_do_command("-t mangle -A "+CHAIN_INCOMING+" -d %s -j MARK %s 0x%x%x", client.ip, markop, client.idx+10, FW_MARK_AUTHENTICATED)

	/* This rule is just for download (incoming) byte counting, see iptables_fw_counters_update() */
	rc |= iptables_do_command("-t mangle -A "+CHAIN_INCOMING+" -d %s -j ACCEPT", client.ip)
}

func HelloAction(w http.ResponseWriter, req *http.Request) {
	w.Header().Set("Content-Type", "text/html")
	w.Write([]byte("Hello, world\n"))
	w.Write([]byte(fmt.Sprintf("%v", time.Now())))
}

func AuthAction(w http.ResponseWriter, req *http.Request) {
	// req.RemoteAddr is in the form of ip:port. Trim the port.
	client_ip := req.RemoteAddr[:strings.LastIndex(req.RemoteAddr, ":")]
	client_mac := arp_get(client_ip)
	client_idx := 1
	iptables_fw_access(Client{client_ip, client_mac, client_idx})

	w.Header().Set("Content-Type", "text/html")
	w.Write([]byte(fmt.Sprintf("Authenticated %v\n", client_ip)))
	w.Write([]byte(fmt.Sprintf("%v", time.Now())))
}

func main() {
	iptables_init()
	log.Println("Initialized iptables rules")

	http.HandleFunc("/", HelloAction)
	http.HandleFunc("/auth", AuthAction)
	http.ListenAndServe(":2050", nil)
	log.Println("Started web server")
}
