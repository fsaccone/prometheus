/* See LICENSE file for copyright and license details. */

#include <dirent.h>
#include <errno.h>
#include <signal.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include "arg.h"
#include "config.h"

struct Depend {
	char *pname;
	unsigned int runtime;
};

struct DependNode {
	struct Depend v;
	struct DependNode *n;
};

struct Source {
	char *url;
	uint8_t sha256[32];
	char *relpath;
};

struct SourceNode {
	struct Source v;
	struct SourceNode *n;
};

struct StringNode {
	char *v;
	struct StringNode *n;
};

static char *chdirtotmp(char *pname, char *prefix);
static void die(const char *m, ...);
static unsigned int direxists(const char *f);
static unsigned int execfileexists(const char *f);
static char *expandtilde(const char *f);
static unsigned int fileexists(const char *f);
static void freelinkedlist(struct StringNode *n);
static void handlesignals(void(*hdl)(int));
static void installpackage(char *pname, char *prefix, char *tmp);
static struct StringNode *listdirs(const char *d);
static unsigned int packageexists(char *pname);
static struct DependNode *packagedepends(char *pname);
static struct StringNode *packageouts(char *pname);
static struct StringNode *packagerequires(char *pname);
static struct SourceNode *packagesources(char *pname);
static void printinstalled(char *prefix, struct StringNode *pkgs);
static struct StringNode *readlines(const char *f);
static int runpscript(char *prefix, char *tmp, char *script);
static void sigcleanup();
static void uninstallpackage(char *pname, char *prefix, char *tmp,
                             unsigned int rec, struct StringNode *pkgs);
static void usage(void);

char *
chdirtotmp(char *pname, char *prefix)
{
	char tmp[256], cmd[512], *dir, *resdir;

	snprintf(tmp, sizeof(tmp), "%s/tmp", prefix);
	if (mkdir(tmp, 0700) == -1 && errno != EEXIST) {
		perror("mkdir");
		exit(EXIT_FAILURE);
	}

	snprintf(tmp, sizeof(tmp), "%s/tmp/prometheus", prefix);
	if (mkdir(tmp, 0700) == -1 && errno != EEXIST) {
		perror("mkdir");
		exit(EXIT_FAILURE);
	}

	snprintf(tmp, sizeof(tmp), "%s/tmp/prometheus/%s-XXXXXX", prefix,
	                                                          pname);
	if (!(dir = mkdtemp(tmp))) {
		perror("mkdtemp");
		exit(EXIT_FAILURE);
	}

	snprintf(cmd, sizeof(cmd), "cp -rf '%s/%s'/* %s", pkgsrepodir, pname,
	                                                  dir);
	if (system(cmd) == -1) {
		perror("system");
		exit(EXIT_FAILURE);
	}

	if (chdir(dir) != 0) {
		perror("chdir");
		exit(EXIT_FAILURE);
	}

	if (!(resdir = malloc(strlen(dir) + 1))) {
		perror("malloc");
		exit(EXIT_FAILURE);
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
			exit(EXIT_FAILURE);
		}
		strcpy(res, f);
		return res;
	}

	if (!(home = getenv("HOME")))
		die("%s: cannot expand tilde since HOME is undefined", argv0);

	/* -~ +\0 */
	if (!(res = malloc(strlen(home) + strlen(f)))) {
		perror("malloc");
		exit(EXIT_FAILURE);
	}

	strcpy(res, home);
	strcat(res, f + 1); /* skip ~ */

	return res;
}

unsigned int
fileexists(const char *f)
{
	struct stat buf;
	return (!stat(f, &buf));
}

void
freelinkedlist(struct StringNode *n)
{
	while (n) {
		struct StringNode *nn = n->n;
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
installpackage(char *pname, char *prefix, char *tmp)
{
	struct StringNode *deps = readlines("depends"), *dep;

	if (!runpscript(prefix, tmp, "isinstalled")) {
		printf("+ skipping %s since it is already installed\n", pname);
		freelinkedlist(deps);
		return;
	}

	for (dep = deps; dep; dep = dep->n) {
		char *tmp = chdirtotmp(dep->v, prefix);
		printf("+ found dependency %s for %s\n", dep->v, pname);
		if (!packageexists(dep->v)) {
			printf("+ dependency %s does not exist\n", dep->v);
			free(tmp);
			continue;
		}
		installpackage(dep->v, prefix, tmp);
		free(tmp);
	}

	freelinkedlist(deps);

	printf("- building %s\n", pname);
	if (runpscript(prefix, tmp, "build"))
		die("+ failed to build %s, see %s/build.log",
		    pname, tmp);
	printf("+ built %s\n", pname);
}

struct StringNode *
listdirs(const char *f)
{
	DIR *d;
	struct dirent *e;
	struct stat s;
	struct StringNode *head = NULL, *tail = NULL, *n;

	if(!(d = opendir(f))) return NULL;

	while ((e = readdir(d))) {
		if (e->d_name[0] == '.' || !strcmp(e->d_name, ".")
		                        || !strcmp(e->d_name, "..")) {
			continue;
		}

		char path[1024];

		snprintf(path, sizeof(path), "%s/%s", f, e->d_name);

		if (!stat(path, &s) && S_ISDIR(s.st_mode)) {
			if (!(n = malloc(sizeof(struct StringNode)))) {
				closedir(d);
				perror("malloc");
				exit(EXIT_FAILURE);
			}

			if (!(n->v = malloc(strlen(e->d_name) + 1))) {
				free(n);
				closedir(d);
				perror("malloc");
				exit(EXIT_FAILURE);
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
	char bf[1024], of[1024], sf[1024];

	snprintf(bf, sizeof(bf), "%s/%s/build", pkgsrepodir, pname);
	snprintf(of, sizeof(of), "%s/%s/outs", pkgsrepodir, pname);
	snprintf(sf, sizeof(sf), "%s/%s/sources", pkgsrepodir, pname);

	if (execfileexists(bf) && fileexists(of) && fileexists(sf)) return 1;

	return 0;
}

struct DependNode *
packagedepends(char *pname)
{
	char f[1024];
	struct StringNode *l;
	struct DependNode *tail = NULL, *head = NULL;

	snprintf(f, sizeof(f), "%s/%s/depends", pkgsrepodir, pname);
	l = readlines(f);

	for (; l; l = l->n) {
		char dname[65],
		     sndfield[8];
		int nfields;
		struct DependNode *d = malloc(sizeof(struct DependNode));

		dname[0] = '\0';
		sndfield[0] = '\0';

		if ((nfields = sscanf(l->v, "%64s %7s", dname, sndfield)) < 1) {
			free(d);
			die("%s: PACKAGE not present in one of %s's depends",
			    argv0, pname);
		}

		dname[strcspn(dname, "\n")] = '\0';
		if (!(d->v.pname = malloc(strlen(dname) + 1))) {
			free(d);
			perror("malloc");
			exit(1);
		};
		strcpy(d->v.pname, dname);
		d->v.pname[65] = '\0';
		if (nfields < 2) {
			d->v.runtime = 0;
		} else if (!strcmp(sndfield, "runtime")) {
			d->v.runtime = 1;
		} else {
			free(d->v.pname);
			free(d);
			die("%s: the second field in one of %s's depends is "
			    "something different than runtime", argv0, pname);
		}

		d->n = NULL;

		if (!head)
			head = d;
		else
			tail->n = d;

		tail = d;
	}

	return head;
}

struct StringNode *
packageouts(char *pname)
{
	char f[1024];
	snprintf(f, sizeof(f), "%s/%s/outs", pkgsrepodir, pname);
	return readlines(f);
}

struct StringNode *packagerequires(char *pname)
{
	char f[1024];
	snprintf(f, sizeof(f), "%s/%s/requires", pkgsrepodir, pname);
	return readlines(f);
}

struct SourceNode *
packagesources(char *pname)
{
	char f[1024];
	struct StringNode *l;
	struct SourceNode *tail = NULL, *head = NULL;

	snprintf(f, sizeof(f), "%s/%s/sources", pkgsrepodir, pname);
	l = readlines(f);

	for (; l; l = l->n) {
		char url[256],
		     sha256[65],
		     relpath[256];
		uint8_t sha256bin[32];
		int nfields, i;
		struct SourceNode *s = malloc(sizeof(struct SourceNode));

		url[0] = '\0';
		sha256[0] = '\0';
		relpath[0] = '\0';

		if ((nfields = sscanf(l->v, "%255s %64s %255s",
		                     url, sha256, relpath)) < 2) {
			free(s);
			die("%s: URL or SHA256 not present in one of %s's "
			    "sources",argv0, pname);
		}
		sha256[strcspn(sha256, "\n")] = '\0';
		for (i = 0; i < 32; i++) {
			if (sscanf(sha256 + 2 * i, "%2hhx",
			           &sha256bin[i]) != 1) {
				free(s);
				die("%s: Invalid SHA256 format in one of %s's "
				    "sources", argv0, pname);
			}
		}

		if (!(s->v.url = malloc(strlen(url) + 1))) {
			free(s);
			perror("malloc");
			exit(1);
		};
		strcpy(s->v.url, url);
		s->v.url[255] = '\0';

		memcpy(s->v.sha256, sha256bin, sizeof(sha256bin));

		if (nfields == 3) {
			relpath[strcspn(relpath, "\n")] = '\0';
			if (!(s->v.relpath = malloc(strlen(relpath) + 1))) {
				free(s);
				perror("malloc");
				exit(1);
			};
			strcpy(s->v.relpath, relpath);
			s->v.relpath[255] = '\0';
		} else {
			s->v.relpath = NULL;
		}

		s->n = NULL;

		if (!head)
			head = s;
		else
			tail->n = s;

		tail = s;
	}

	return head;
}

void
printinstalled(char *prefix, struct StringNode *pkgs)
{
	struct StringNode *p;

	for (p = pkgs; p; p = p->n) {
		char *dir = chdirtotmp(p->v, prefix);
		if (!runpscript(prefix, dir, "isinstalled"))
			printf("%s\n", p->v);
		free(dir);
	}
}

struct StringNode *
readlines(const char *f)
{
	struct StringNode *head = NULL, *tail = NULL;
	FILE *fp;
	char buf[1024];

	fp = fopen(f, "r");
	if (!fp) return NULL;

	while (fgets(buf,sizeof(buf), fp) != NULL) {
		struct StringNode *newl = malloc(sizeof(struct StringNode));
		if (!newl) {
			fclose(fp);
			perror("malloc");
			exit(EXIT_FAILURE);
		}

		buf[strcspn(buf, "\n")] = '\0';
		if (!(newl->v = malloc(strlen(buf) + 1))) {
			free(newl);
			fclose(fp);
			perror("malloc");
			exit(EXIT_FAILURE);
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
runpscript(char *prefix, char *tmp, char *script)
{
	int c;
	char cmd[1024];

	snprintf(cmd, sizeof(cmd),
	         "prefix=\"%s\" "
	         "PATH=\"%s/bin:$PATH\" "
	         "/bin/sh %s > %s.log 2>&1",
	         prefix, prefix, script, script);

	if(chdir(tmp)) {
		perror("chdir");
		exit(EXIT_FAILURE);
	}

	if ((c = system(cmd)) == -1) {
		perror("system");
		exit(EXIT_FAILURE);
	}

	return WEXITSTATUS(c);
}

void
sigcleanup()
{
	exit(EXIT_FAILURE);
}

void
uninstallpackage(char *pname, char *prefix, char *tmp,
                 unsigned int rec, struct StringNode *pkgs)
{
	struct StringNode *dep, *pkg, *ideps = NULL;

	if (runpscript(prefix, tmp, "isinstalled")) {
		printf("+ skipping %s since it is not installed\n", pname);
		return;
	}

	for (pkg = pkgs; pkg; pkg = pkg->n) {
		struct StringNode *pdeps, *pd;
		char *dir;

		dir = chdirtotmp(pkg->v, prefix);
		pdeps = readlines("depends");

		for (pd = pdeps; pd; pd = pd->n) {
			if (!strcmp(pd->v, pname)
			    && !runpscript(prefix, dir, "isinstalled")) {
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

	if (chdir(tmp)) {
		perror("chdir");
		exit(EXIT_FAILURE);
	}

	if (rec) {
		struct StringNode *deps = readlines("depends"),
		                  *idepstail = NULL;

		for (dep = deps; dep; dep = dep->n) {
			struct StringNode *newidep;

			printf("+ found dependency %s for %s\n",
			       dep->v, pname);

			if (!packageexists(dep->v)) {
				printf("+ dependency %s does not exist\n",
				       dep->v);
				continue;
			}

			if (!(newidep = malloc(sizeof(struct StringNode)))) {
				perror("malloc");
				exit(EXIT_FAILURE);
			}
			if (!(newidep->v = malloc(strlen(dep->v) + 1))) {
				free(newidep);
				perror("malloc");
				exit(EXIT_FAILURE);
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

	printf("- uninstalling %s\n", pname);
	if (runpscript(prefix, tmp, "uninstall"))
		die("+ failed to uninstall %s, see %s/uninstall.log",
		    pname, tmp);
	printf("+ uninstalled %s\n", pname);

	for (dep = ideps; dep; dep = dep->n) {
		char *dir = chdirtotmp(dep->v, prefix);
		uninstallpackage(dep->v, prefix, dir, rec, pkgs);
		free(dir);
	}

	freelinkedlist(ideps);
}

void
usage(void)
{
	die("usage: %s [-u [-r]] [-p prefix] package ...\n"
	    "       %s -l [-p prefix]", argv0, argv0);
}

int
main(int argc, char *argv[])
{
	int uninstall = 0,
	    recuninstall = 0,
	    printinst = 0;
	char *prefix = defaultprefix;
	unsigned int expprefix = 0;

	ARGBEGIN {
	case 'l':
		printinst = 1;
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

	if (printinst && argc)
		usage();

	if (!printinst && !argc)
		usage();

	if (printinst && uninstall)
		usage();

	if (recuninstall && !uninstall)
		usage();

	handlesignals(sigcleanup);

	if (prefix[strlen(prefix) - 1] == '/')
		prefix[strlen(prefix) - 1] = '\0';

	if (strlen(prefix) && !direxists(prefix))
		die("%s: prefix %s does not exist", argv0, prefix);

	if (printinst) {
		struct StringNode *pkgs = listdirs(pkgsrepodir);
		printinstalled(prefix, pkgs);
		freelinkedlist(pkgs);
	}

	/* will not be evaluated when printinst is 1 */
	for (; *argv; argc--, argv++) {
		char *tmp;

		if (!packageexists(*argv))
			die("%s: package %s does not exist", argv0, *argv);

		tmp = chdirtotmp(*argv, prefix);

		if (uninstall) {
			struct StringNode *pkgs = listdirs(pkgsrepodir);
			uninstallpackage(*argv, prefix, tmp,
			                 recuninstall, pkgs);
			freelinkedlist(pkgs);
		} else {
			installpackage(*argv, prefix, tmp);
		}

		free(tmp);
	}

	if (expprefix) free(prefix);

	return EXIT_SUCCESS;
}
