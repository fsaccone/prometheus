/* See LICENSE file for copyright and license details. */

#include <signal.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

#include "arg.h"
#include "config.h"

static void die(const char *m, ...);
static unsigned int fileexists(const char *f);
static void handlesignals(void(*hdl)(int));
static unsigned int packageexists(char *p);
static char **readlines(const char *f, size_t *lcount);
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

char **
readlines(const char *f, size_t *lcount)
{
	FILE *fp;
	char **l;
	size_t cap, lsize;

	fp = fopen(f, "r");
	if (!fp) return NULL;

	*lcount = 0;
	cap = 8;
	if(!(l = malloc(cap * sizeof(char *)))) {
		fclose(fp);
		perror("malloc");
		exit(1);
	};

	lsize = 0;
	while (getline(&l[*lcount], &lsize, fp) != -1) {
		size_t llen = strlen(l[*lcount]);
		if (llen > 0 && l[*lcount][llen - 1] == '\n') {
			l[*lcount][llen - 1] = '\0';
		}

		if (*lcount >= cap) {
			cap *= 2;
			if(!(l = realloc(l, cap * sizeof(char *)))) {
				fclose(fp);
				perror("malloc");
				exit(1);
			};
		}

		(*lcount)++;
	}

	fclose(fp);
	return l;
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

	for (; *argv; argc--, argv++) {
		if (!packageexists(*argv)) {
			die("%s: package %s does not exist", argv0, *argv);
		}
	}

	return EXIT_SUCCESS;
}
