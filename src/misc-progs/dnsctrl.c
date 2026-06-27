/* This file is part of the IPFire Firewall.
 *
 * This program is distributed under the terms of the GNU General Public
 * Licence.  See the file COPYING for details.
 *
 */

#include <stdio.h>
#include <string.h>

#include "setuid.h"

int main(int argc, char** argv) {
	// Become root
	if (!initsetuid())
		exit(1);

	// Check if we have enough arguments
	if (argc < 2) {
		fprintf(stderr, "\nNot enough arguments.\n\n");
		exit(1);
	}

	if (strcmp(argv[1], "reload") == 0) {
		char* args[] = {
			"reload", NULL,
		};

		return run("/etc/rc.d/init.d/knot-resolver", args);

	} else if (strcmp(argv[1], "sync-rpzs") == 0) {
		char* args[] = {
			NULL,
		};

		return run("/usr/local/bin/update-rpzs", args);
	}
 
	fprintf(stderr, "Invalid command\n");
	exit(1);
}
