/* See LICENSE file for copyright and license details. */

#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>

#include "arg.h"

static void die(const char *m, ...);
static void usage(void);

void
die(const char *m, ...)
{
	va_list va;
	va_start(va, m);
	vfprintf(stderr, m, va);
	putc('\n', stderr);
	va_end(va);
	exit(EXIT_FAILURE);
}

void
usage(void)
{
	die("usage: %s [-u [-r]] package ...", argv0);
}

int
main(int argc, char *argv[])
{
	int uninstall = 0,
	    recuninstall = 0;

	ARGBEGIN {
	case 'r':
		recuninstall = 1;
		break;
	case 'u':
		uninstall = 1;
		break;
	default:
		usage();
	} ARGEND

	if (!argc) {
		usage();
	}

	if (recuninstall && !uninstall) {
		usage();
	}

	return EXIT_SUCCESS;
}
