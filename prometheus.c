/* See LICENSE file for copyright and license details. */

#include <errno.h>
#include <signal.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include "arg.h"
#include "config.h"

struct Node {
	char *v;
	struct Node *n;
};

static char *chdirtotmp(char *pname, char *prefix);
static void die(const char *m, ...);
static unsigned int fileexists(const char *f);
static void handlesignals(void(*hdl)(int));
static unsigned int packageexists(char *pname);
static struct Node *readlines(const char *f);
static void sigcleanup(int sig);
static void usage(void);

char *
chdirtotmp(char *pname, char *prefix)
{
	char tmp[256], cmd[512], *dir, *resdir;

	snprintf(tmp, sizeof(tmp), "%s/tmp", prefix);
	if (mkdir(tmp, 0700) == -1 && errno != EEXIST) {
		perror("mkdir");
		exit(1);
	}

	snprintf(tmp, sizeof(tmp), "%s/tmp/prometheus", prefix);
	if (mkdir(tmp, 0700) == -1 && errno != EEXIST) {
		perror("mkdir");
		exit(1);
	}

	snprintf(tmp, sizeof(tmp), "%s/tmp/prometheus/%s-XXXXXX", prefix,
	                                                          pname);
	if (!(dir = mkdtemp(tmp))) {
		perror("mkdtemp");
		exit(1);
	}

	snprintf(cmd, sizeof(cmd), "cp -rf '%s/%s'/* %s", pkgsrepopath, pname,
	                                                  dir);
	if (system(cmd) == -1) {
		perror("system");
		exit(1);
	}

	if (chdir(dir) != 0) {
		perror("chdir");
		exit(1);
	}

	if (!(resdir = malloc(strlen(dir) + 1))) {
		perror("malloc");
		exit(1);
	}
	strcpy(resdir, dir);

	return resdir;
}

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
packageexists(char *pname)
{
	char f[1024];

	snprintf(f, sizeof(f), "%s/%s/retrieve", pkgsrepopath, pname);
	if (!fileexists(f)) return 0;

	snprintf(f, sizeof(f), "%s/%s/configure", pkgsrepopath, pname);
	if (!fileexists(f)) return 0;

	snprintf(f, sizeof(f), "%s/%s/build", pkgsrepopath, pname);
	if (!fileexists(f)) return 0;

	snprintf(f, sizeof(f), "%s/%s/test", pkgsrepopath, pname);
	if (!fileexists(f)) return 0;

	snprintf(f, sizeof(f), "%s/%s/install", pkgsrepopath, pname);
	if (!fileexists(f)) return 0;

	snprintf(f, sizeof(f), "%s/%s/uninstall", pkgsrepopath, pname);
	if (!fileexists(f)) return 0;

	snprintf(f, sizeof(f), "%s/%s/isinstalled", pkgsrepopath, pname);
	if (!fileexists(f)) return 0;

	return 1;
}

struct Node *
readlines(const char *f)
{
	struct Node *head = NULL, *tail = NULL;
	FILE *fp;
	char buf[1024];

	fp = fopen(f, "r");
	if (!fp) return NULL;

	while (fgets(buf,sizeof(buf), fp) != NULL) {
		struct Node *newl = malloc(sizeof(struct Node));
		if (!newl) {
			fclose(fp);
			perror("malloc");
			exit(1);
		}

		buf[strcspn(buf, "\n")] = '\0';
		if (!(newl->v = malloc(strlen(buf) + 1))) {
			free(newl);
			fclose(fp);
			perror("malloc");
			exit(1);
		}
		strcpy(newl->v, buf);

		newl->n = NULL;

		if (!head)
			head = newl;
		else
			tail->n = newl;

		tail = newl;
	}

	fclose(fp);
	return head;
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
		char *tmp;
		struct Node *dep;

		if (!packageexists(*argv)) {
			die("%s: package %s does not exist", argv0, *argv);
		}

		tmp = chdirtotmp(*argv, prefix);
		dep = readlines("dependencies");
	}

	return EXIT_SUCCESS;
}
