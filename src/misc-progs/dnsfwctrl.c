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
		fprintf(stderr, "\nNo argument given.\n\ndnsfwctrl (start|stop|restart|sync|clear|status)\n\n");
		exit(1);
	}

	if (strcmp(argv[1], "start") == 0) {
		safe_system("/etc/rc.d/init.d/dnsfw start");
	} else if (strcmp(argv[1], "stop") == 0) {
		safe_system("/etc/rc.d/init.d/dnsfw stop");
	} else if (strcmp(argv[1], "restart") == 0) {
		safe_system("/etc/rc.d/init.d/dnsfw restart");
	} else if (strcmp(argv[1], "clear") == 0) {
		safe_system("/usr/sbin/dns_fw /sys/fs/bpf/dns-fw/dns_fw_blocklist clear");
	} else if (strcmp(argv[1], "sync") == 0) {
		safe_system("/usr/sbin/dns_fw /sys/fs/bpf/dns-fw/dns_fw_blocklist sync");
	} else if (strcmp(argv[1], "status") == 0) {
		safe_system("/etc/rc.d/init.d/dnsfw status");
	} else {
		fprintf(stderr, "\nBad argument given.\n\ndnsfwctrl (start|stop|restart|clear|sync|status)\n\n");
		exit(1);
	}

	return 0;
}
