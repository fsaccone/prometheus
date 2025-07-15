/* See LICENSE file for copyright and license details. */

#include <dirent.h>
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
static unsigned int direxists(const char *f);
static unsigned int execfileexists(const char *f);
static char *expandtilde(const char *f);
static void freelinkedlist(struct Node *n);
static void handlesignals(void(*hdl)(int));
static void installpackage(char *pname, char *cc, char *prefix, char *tmp);
static struct Node *listdirs(const char *d);
static unsigned int packageexists(char *pname);
static struct Node *readlines(const char *f);
static int runpscript(char *prefix, char *cc, char *tmp, char *script);
static void sigcleanup(int sig);
static void uninstallpackage(char *pname, char *cc, char *prefix, char *tmp,
                             unsigned int rec, struct Node *pkgs);
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

	snprintf(cmd, sizeof(cmd), "cp -rf '%s/%s'/* %s", pkgsrepodir, pname,
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
direxists(const char *f)
{
	struct stat buf;
	if (stat(f, &buf) != 0) return 0;
	if (S_ISDIR(buf.st_mode)) return 1;
	return 0;
}

unsigned int
execfileexists(const char *f)
{
	struct stat buf;
	if (stat(f, &buf) != 0) return 0;
	if (buf.st_mode & (S_IXUSR | S_IXGRP | S_IXOTH)) return 1;
	return 0;
}

char *
expandtilde(const char *f)
{
	char *home, *res;

	if (f[0] != '~') {
		if (!(res = malloc(strlen(f) + 1))) {
			perror("malloc");
			exit(1);
		}
		strcpy(res, f);
		return res;
	}

	if (!(home = getenv("HOME")))
		die("%s: cannot expand tilde since HOME is undefined", argv0);

	/* -~ +\0 */
	if (!(res = malloc(strlen(home) + strlen(f)))) {
		perror("malloc");
		exit(1);
	}

	strcpy(res, home);
	strcat(res, f + 1); /* skip ~ */

	return res;
}

void
freelinkedlist(struct Node *n)
{
	while (n) {
		struct Node *nn = n->n;
		free(n->v);
		free(n);
		n = nn;
	}
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

void
installpackage(char *pname, char *cc, char *prefix, char *tmp)
{
	struct Node *deps = readlines("dependencies"), *dep;

	if (!runpscript(prefix, cc, tmp, "isinstalled")) {
		printf("+ skipping %s since it is already installed\n", pname);
		freelinkedlist(deps);
		return;
	}

	for (dep = deps; dep; dep = dep->n) {
		char *tmp = chdirtotmp(dep->v, prefix);
		printf("+ found dependency %s for %s\n", dep->v, pname);
		installpackage(dep->v, cc, prefix, tmp);
		free(tmp);
	}

	freelinkedlist(deps);

	if(chdir(tmp)) {
		perror("chdir");
		exit(1);
	}
	printf("- retrieving %s\n", pname);
	if (runpscript(prefix, cc, tmp, "retrieve"))
		die("%s: failed to retrieve %s, see %s/retrieve.log",
		    argv0, pname, tmp);
	printf("+ retrieved %s\n", pname);

	if(chdir(tmp)) {
		perror("chdir");
		exit(1);
	}
	printf("- configuring %s\n", pname);
	if (runpscript(prefix, cc, tmp, "configure"))
		die("%s: failed to configure %s, see %s/configure.log",
		    argv0, pname, tmp);
	printf("+ configured %s\n", pname);

	if(chdir(tmp)) {
		perror("chdir");
		exit(1);
	}
	printf("- building %s\n", pname);
	if (runpscript(prefix, cc, tmp, "build"))
		die("%s: failed to build %s, see %s/build.log",
		    argv0, pname, tmp);
	printf("+ built %s\n", pname);

	if(chdir(tmp)) {
		perror("chdir");
		exit(1);
	}
	printf("- testing %s\n", pname);
	if (runpscript(prefix, cc, tmp, "test"))
		die("%s: failed to test %s, see %s/test.log",
		    argv0, pname, tmp);
	printf("+ tested %s\n", pname);

	if(chdir(tmp)) {
		perror("chdir");
		exit(1);
	}
	printf("- installing %s\n", pname);
	if (runpscript(prefix, cc, tmp, "install"))
		die("%s: failed to install %s, see %s/install.log",
		    argv0, pname, tmp);
	printf("+ installed %s\n", pname);
}

struct Node *
listdirs(const char *f)
{
	DIR *d;
	struct dirent *e;
	struct stat s;
	struct Node *head = NULL, *tail = NULL, *n;

	if(!(d = opendir(f))) return NULL;

	while ((e = readdir(d))) {
		if (e->d_name[0] == '.' || !strcmp(e->d_name, ".")
		                        || !strcmp(e->d_name, "..")) {
			continue;
		}

		char path[1024];

		snprintf(path, sizeof(path), "%s/%s", f, e->d_name);

		if (!stat(path, &s) && S_ISDIR(s.st_mode)) {
			if (!(n = malloc(sizeof(struct Node)))) {
				closedir(d);
				perror("malloc");
				exit(1);
			}

			if (!(n->v = malloc(strlen(e->d_name) + 1))) {
				free(n);
				closedir(d);
				perror("malloc");
				exit(1);
			}

			strcpy(n->v, e->d_name);

			n->n = NULL;

			if (!head)
				head = n;
			else
				tail->n = n;

			tail = n;
		}
	}

	closedir(d);
	return head;
}

unsigned int
packageexists(char *pname)
{
	char f[1024];

	snprintf(f, sizeof(f), "%s/%s/retrieve", pkgsrepodir, pname);
	if (!execfileexists(f)) return 0;

	snprintf(f, sizeof(f), "%s/%s/configure", pkgsrepodir, pname);
	if (!execfileexists(f)) return 0;

	snprintf(f, sizeof(f), "%s/%s/build", pkgsrepodir, pname);
	if (!execfileexists(f)) return 0;

	snprintf(f, sizeof(f), "%s/%s/test", pkgsrepodir, pname);
	if (!execfileexists(f)) return 0;

	snprintf(f, sizeof(f), "%s/%s/install", pkgsrepodir, pname);
	if (!execfileexists(f)) return 0;

	snprintf(f, sizeof(f), "%s/%s/uninstall", pkgsrepodir, pname);
	if (!execfileexists(f)) return 0;

	snprintf(f, sizeof(f), "%s/%s/isinstalled", pkgsrepodir, pname);
	if (!execfileexists(f)) return 0;

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

int
runpscript(char *prefix, char *cc, char *tmp, char *script)
{
	int c;
	char cmd[1024];

	snprintf(cmd, sizeof(cmd),
	         "cc=\"%s\" "
	         "prefix=\"%s\" "
	         "PATH=\"%s/bin:$PATH\" "
	         "/bin/sh %s > %s.log 2>&1",
	         cc, prefix, prefix, script, script);

	if(chdir(tmp)) {
		perror("chdir");
		exit(1);
	}

	if ((c = system(cmd)) == -1) {
		perror("system");
		exit(1);
	}

	return WEXITSTATUS(c);
}

void
sigcleanup(int sig)
{
	exit(1);
}

void
uninstallpackage(char *pname, char *cc, char *prefix, char *tmp,
                 unsigned int rec, struct Node *pkgs)
{
	struct Node *dep, *pkg, *ideps = NULL;

	if (runpscript(prefix, cc, tmp, "isinstalled")) {
		printf("+ skipping %s since it is not installed\n", pname);
		return;
	}

	for (pkg = pkgs; pkg; pkg = pkg->n) {
		struct Node *pdeps, *pd;
		char *dir;

		dir = chdirtotmp(pkg->v, prefix);
		if (!runpscript(prefix, cc, tmp, "isinstalled")) {
			free(dir);
			continue;
		}

		pdeps = readlines("dependencies");

		for (pd = pdeps; pd; pd = pd->n) {
			if (!strcmp(pd->v, pname)) {
				printf("+ skipping %s since %s depends on "
				       "it\n", pname, pkg->v);
				free(dir);
				freelinkedlist(pdeps);
				return;
			}
		}

		free(dir);
		freelinkedlist(pdeps);
	}

	if (rec) {
		struct Node *deps = readlines("dependencies"),
		            *idepstail = NULL;

		for (dep = deps; dep; dep = dep->n) {
			struct Node *newidep;

			printf("+ found dependency %s for %s\n",
			       dep->v, pname);

			if (!(newidep = malloc(sizeof(struct Node)))) {
				perror("malloc");
				exit(1);
			}
			if (!(newidep->v = malloc(strlen(dep->v) + 1))) {
				free(newidep);
				perror("malloc");
				exit(1);
			}
			strcpy(newidep->v, dep->v);

			newidep->n = NULL;

			if (!ideps)
				ideps = newidep;
			else
				idepstail->n = newidep;

			idepstail = newidep;
		}

		freelinkedlist(deps);
	}

	if(chdir(tmp)) {
		freelinkedlist(ideps);
		perror("chdir");
		exit(1);
	}
	printf("- uninstalling %s\n", pname);
	if (runpscript(prefix, cc, tmp, "uninstall"))
		die("%s: failed to uninstall %s, see %s/uninstall.log",
		    argv0, pname, tmp);
	printf("+ uninstalled %s\n", pname);

	for (dep = ideps; dep; dep = dep->n) {
		char *dir = chdirtotmp(dep->v, prefix);
		uninstallpackage(dep->v, cc, prefix, dir, rec, pkgs);
		free(dir);
	}

	freelinkedlist(ideps);
}

void
usage(void)
{
	die("usage: %s [-u [-r]] [-c ccompiler] "
	    "[-p prefix] package ...", argv0);
}

int
main(int argc, char *argv[])
{
	int uninstall = 0,
	    recuninstall = 0;
	char *cc = "cc",
	     *prefix = defaultprefix;
	unsigned int expprefix = 0;

	ARGBEGIN {
	case 'c':
		cc = EARGF(usage());
		break;
	case 'p':
		char *arg = EARGF(usage());
		prefix = expandtilde(arg);
		if (arg != prefix) expprefix = 1;
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

	if (prefix[strlen(prefix) - 1] == '/')
		prefix[strlen(prefix) - 1] = '\0';

	if (strlen(prefix) && !direxists(prefix)
	                   && mkdir(prefix, 0700) == -1) {
		perror("mkdir");
		exit(1);
	}

	for (; *argv; argc--, argv++) {
		char *tmp;

		if (!packageexists(*argv)) {
			die("%s: package %s does not exist", argv0, *argv);
		}

		tmp = chdirtotmp(*argv, prefix);

		if (uninstall) {
			struct Node *pkgs = listdirs(pkgsrepodir);
			uninstallpackage(*argv, cc, prefix, tmp,
			                 recuninstall, pkgs);
			freelinkedlist(pkgs);
		} else {
			installpackage(*argv, cc, prefix, tmp);
		}

		free(tmp);
	}

	if (expprefix) free(prefix);

	return EXIT_SUCCESS;
}
