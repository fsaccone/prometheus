/* See LICENSE file for copyright and license details. */

#include <signal.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/stat.h>

#include "arg.h"
#include "config.h"

static void die(const char *m, ...);
static unsigned int fileexists(const char *f);
static void handlesignals(void(*hdl)(int));
static unsigned int packageexists(char *p);
static void sigcleanup(int sig);
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

unsigned int
fileexists(const char *f)
{
	struct stat buf;
	return (stat(f, &buf) == 0);
}

void
handlesignals(void(*hdl)(int))
{
	struct sigaction sa = {
		.sa_handler = hdl,
	};

	sigemptyset(&sa.sa_mask);
	sigaction(SIGTERM, &sa, NULL);
	sigaction(SIGHUP, &sa, NULL);
	sigaction(SIGINT, &sa, NULL);
	sigaction(SIGQUIT, &sa, NULL);
}

unsigned int
packageexists(char *p)
{
	char f[1024];

	snprintf(f, sizeof(f), "%s/%s/retrieve", pkgsrepopath, p);
	if (!fileexists(f)) return 0;

	snprintf(f, sizeof(f), "%s/%s/configure", pkgsrepopath, p);
	if (!fileexists(f)) return 0;

	snprintf(f, sizeof(f), "%s/%s/build", pkgsrepopath, p);
	if (!fileexists(f)) return 0;

	snprintf(f, sizeof(f), "%s/%s/test", pkgsrepopath, p);
	if (!fileexists(f)) return 0;

	snprintf(f, sizeof(f), "%s/%s/install", pkgsrepopath, p);
	if (!fileexists(f)) return 0;

	snprintf(f, sizeof(f), "%s/%s/uninstall", pkgsrepopath, p);
	if (!fileexists(f)) return 0;

	snprintf(f, sizeof(f), "%s/%s/isinstalled", pkgsrepopath, p);
	if (!fileexists(f)) return 0;

	return 1;
}

void
sigcleanup(int sig)
{
	exit(1);
}

void
usage(void)
{
	die("usage: %s [-u [-r]] [-p prefix] package ...", argv0);
}

int
main(int argc, char *argv[])
{
	int uninstall = 0,
	    recuninstall = 0;
	char *prefix = "";

	ARGBEGIN {
	case 'p':
		prefix = EARGF(usage());
		break;
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

	handlesignals(sigcleanup);

	return EXIT_SUCCESS;
}
