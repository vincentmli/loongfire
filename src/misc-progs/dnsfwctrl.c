/* This file is part of the LoongFire Firewall.
 *
 * This program is distributed under the terms of the GNU General Public
 * Licence.  See the file COPYING for details.
 *
 */

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <fcntl.h>
#include "setuid.h"

int main(int argc, char *argv[]) {

	if (!(initsetuid()))
		exit(1);

	if (argc < 2) {
		fprintf(stderr, "\nNo argument given.\n\ndnsfwctrl (start|stop|restart|sync|clear|status|custom-sync|custom-reload|custom-clear|custom-status)\n\n");
		exit(1);
	}

	if (strcmp(argv[1], "start") == 0) {
		safe_system("/etc/rc.d/init.d/dnsfw start");
	} else if (strcmp(argv[1], "stop") == 0) {
		safe_system("/etc/rc.d/init.d/dnsfw stop");
	} else if (strcmp(argv[1], "restart") == 0) {
		safe_system("/etc/rc.d/init.d/dnsfw restart");
	} else if (strcmp(argv[1], "clear") == 0) {
		// Clear both blocklist and custom map
		safe_system("/usr/sbin/dns_fw /sys/fs/bpf/dns-fw/dns_fw_blocklist clear");
		safe_system("/usr/sbin/dns_fw /sys/fs/bpf/dns-fw/dns_fw_custom_map custom-clear");
	} else if (strcmp(argv[1], "sync") == 0) {
		safe_system("/etc/rc.d/init.d/dnsfw sync");
	} else if (strcmp(argv[1], "status") == 0) {
		safe_system("/etc/rc.d/init.d/dnsfw status");
	} else if (strcmp(argv[1], "custom-sync") == 0) {
		safe_system("/etc/rc.d/init.d/dnsfw custom-sync");
	} else if (strcmp(argv[1], "custom-reload") == 0) {
		safe_system("/etc/rc.d/init.d/dnsfw custom-reload");
	} else if (strcmp(argv[1], "custom-clear") == 0) {
		safe_system("/etc/rc.d/init.d/dnsfw custom-clear");
	} else if (strcmp(argv[1], "custom-status") == 0) {
		safe_system("/etc/rc.d/init.d/dnsfw custom-status");
	} else {
		fprintf(stderr, "\nBad argument given.\n\ndnsfwctrl (start|stop|restart|clear|sync|status|custom-sync|custom-reload|custom-clear|custom-status)\n\n");
		exit(1);
	}

	return 0;
}
