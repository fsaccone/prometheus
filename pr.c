/* See LICENSE file for copyright and license details. */

#define _DEFAULT_SOURCE
#define _POSIX_C_SOURCE 200809L
#define _XOPEN_SOURCE   700

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <libgen.h>
#include <limits.h>
#include <signal.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <termios.h>
#include <unistd.h>

#define REQUESTS_IMPLEMENTATION
#include "requests.h"

#include "arg.h"
#include "config.h"
#undef SHA256_DIGEST_LENGTH
#include "sha256.h"

#define LINES_MAX     MAX(MAX(DEPENDS_MAX, OUTS_MAX), SOURCES_MAX)
#define MAX(a, b)     ((a) > (b) ? (a) : (b))
#define TMPFILE       "/tmp/prXXXXXX"
#define TMPFILE_SIZE  14

struct Depend {
	char pname[NAME_MAX];
	unsigned int runtime;
};

struct Depends {
	struct Depend a[DEPENDS_MAX];
	size_t l;
};

struct Lines {
	char a[LINES_MAX][LINE_MAX];
	size_t l;
};

struct Outs {
	char a[OUTS_MAX][PATH_MAX];
	size_t l;
};

struct Package {
	char pname[NAME_MAX];
	char srcd[PATH_MAX];
	char destd[PATH_MAX];
	unsigned int build;
};

struct PackageNames {
	char a[PACKAGES_MAX][NAME_MAX];
	size_t l;
};

struct PackageNode {
	struct Package *p;
	struct PackageNode *n;
};

struct PathNode {
	char p[PATH_MAX];
	struct PathNode *n;
};

struct Source {
	uint8_t sha256[SHA256_DIGEST_LENGTH];
	char url[PATH_MAX];
	char relpath[PATH_MAX];
};

struct Sources {
	struct Source a[SOURCES_MAX];
	size_t l;
};

static void cleanup(void);
static int pnamecmp(const char **a, const char **b);
static int copydirrecursive(const char s[PATH_MAX], const char d[PATH_MAX]);
static int copyfile(const char s[PATH_MAX], const char d[PATH_MAX],
                    unsigned int ressym);
static int createtmpdir(char dir[TMPFILE_SIZE]);
static unsigned int direxists(const char f[PATH_MAX]);
static int expandtilde(const char f[PATH_MAX], char ef[PATH_MAX]);
static int fetchfile(char url[PATH_MAX], const char f[PATH_MAX]);
static unsigned int fileexists(const char f[PATH_MAX]);
static int getpackages(struct PackageNames *pkgs);
static void handlesignals(void(*hdl)(int));
static int installouts(struct Outs outs, const char sd[PATH_MAX],
                       const char dd[PATH_MAX]);
static int installpackage(struct Package p);
static int mkdirrecursive(const char d[PATH_MAX]);
static int packagedepends(char pname[NAME_MAX], struct Depends *deps);
static int packageexists(const char pname[NAME_MAX]);
static int packageisinstalled(char pname[NAME_MAX],
                              const char destd[PATH_MAX]);
static unsigned int packageisnochroot(char pname[NAME_MAX]);
static int packageouts(char pname[NAME_MAX], struct Outs *outs);
static int packagesources(char pname[NAME_MAX], struct Sources *srcs);
static void printerrno(const char *s);
static void printferr(const char *m, ...);
static int printinstalled(struct PackageNames pkgs);
static void printpackages(struct PackageNames pkgs);
static int readlines(const char f[PATH_MAX], struct Lines *l);
static int registerpackageinstall(struct Package *p);
static int registerpackageuninstall(struct Package *p, unsigned int rec);
static unsigned int relpathisvalid(char relpath[PATH_MAX]);
static void requestscallback(struct download_state* s, char *p[PATH_MAX]);
static int rmdirrecursive(const char d[PATH_MAX]);
static int retrievesources(struct Sources srcs, const char pdir[PATH_MAX],
                           const char tmpd[PATH_MAX]);
static void sha256chartouint8(const char c[2 * SHA256_DIGEST_LENGTH + 1],
                              uint8_t u[SHA256_DIGEST_LENGTH]);
static int sha256hash(const char f[PATH_MAX], uint8_t h[SHA256_DIGEST_LENGTH]);
static void sha256uint8tochar(const uint8_t u[SHA256_DIGEST_LENGTH],
                              char c[2 * SHA256_DIGEST_LENGTH + 1]);
static void sigexit();
static int sortpackages(struct PackageNames *pkgs);
static int uninstallpackage(struct Package p);
static unsigned int urlisvalid(const char url[PATH_MAX]);
static void usage(void);

static struct termios oldt;
static struct PackageNode *reqpkgshead = NULL;
static char prefix[PATH_MAX];
static char repository[PATH_MAX];
static struct PathNode *tmpdirhead = NULL;

void
cleanup(void)
{
	struct PackageNode *pn, *pnn;
	struct PathNode *tmpd, *tmpdn;

	for (pn = reqpkgshead; pn; pn = pnn) {
		pnn = pn->n;
		if (pn->p) free(pn->p);
		free(pn);
	}

	printf("\r\033[K");
	fflush(stdout);

	if (!tmpdirhead) return;

	printf("- Cleaning up");

	for (tmpd = tmpdirhead; tmpd; tmpd = tmpdn) {
		tmpdn = tmpd->n;
		(void)rmdirrecursive(tmpd->p);
		free(tmpd);
	}

	printf("\r\033[K");
	fflush(stdout);
}

int
pnamecmp(const char **a, const char **b)
{
	return strncmp(*a, *b, NAME_MAX);
}

int
copydirrecursive(const char s[PATH_MAX], const char d[PATH_MAX])
{
	DIR *df;
	struct dirent *e;

	if (!direxists(d) && mkdirrecursive(d)) return EXIT_FAILURE;

	if (!(df = opendir(s))) {
		printerrno("opendir");
		return EXIT_FAILURE;
	}

	while ((e = readdir(df))) {
		char sp[PATH_MAX], dp[PATH_MAX];

		if (!strcmp(e->d_name, ".") || !strcmp(e->d_name, ".."))
			continue;

		strncat(sp, s,         sizeof(sp) - strlen(sp) - 1);
		strncat(sp, "/",       sizeof(sp) - strlen(sp) - 1);
		strncat(sp, e->d_name, sizeof(sp) - strlen(sp) - 1);

		strncat(dp, d,         sizeof(dp) - strlen(dp) - 1);
		strncat(dp, "/",       sizeof(dp) - strlen(dp) - 1);
		strncat(dp, e->d_name, sizeof(dp) - strlen(dp) - 1);

		if (direxists(sp)) {
			char *spc, *dpc;

			if (!(spc = malloc(sizeof(sp)))) {
				printerrno("malloc");
				return EXIT_FAILURE;
			}
			if (!(dpc = malloc(sizeof(dp)))) {
				free(spc);
				printerrno("malloc");
				return EXIT_FAILURE;
			}

			strncpy(spc, sp, PATH_MAX);
			strncpy(dpc, dp, PATH_MAX);

			if (copydirrecursive(spc, dpc)) {
				free(spc);
				free(dpc);
				return EXIT_FAILURE;
			}

			free(spc);
			free(dpc);
		} else if (copyfile(sp, dp, 1)) {
			return EXIT_FAILURE;
		}
	}

	return EXIT_SUCCESS;
}

int
copyfile(const char s[PATH_MAX], const char d[PATH_MAX],
         unsigned int ressym)
{
	int sfd, dfd;
	char buf[1024], rs[PATH_MAX], dc[PATH_MAX];
	struct stat sbuf;
	const char *dn;
	ssize_t b;

	if (lstat(s, &sbuf)) {
		printerrno("lstat");
		return EXIT_FAILURE;
	}

	if (!ressym && S_ISLNK(sbuf.st_mode)) {
		char sc[PATH_MAX], *sdn, lnk[PATH_MAX];
		int lnkl, sdd;

		strncpy(sc, s, PATH_MAX);
		sdn = dirname(sc);

		if ((sdd = open(sdn, O_DIRECTORY)) == -1) {
			printerrno("open");
			return EXIT_FAILURE;
		}

		if ((lnkl = readlinkat(sdd, s, lnk, PATH_MAX)) == -1) {
			close(sdd);
			printerrno("readlinkat");
			return EXIT_FAILURE;
		}
		lnk[lnkl] = '\0';
		close(sdd);

		if (fileexists(d) && remove(d)) {
			printerrno("remove");
			return EXIT_FAILURE;
		}

		if (direxists(d) && rmdirrecursive(d)) return EXIT_FAILURE;

		strncpy(dc, d, PATH_MAX);
		dn = dirname(dc);
		if (mkdirrecursive(dn)) return EXIT_FAILURE;

		if (symlink(lnk, d)) {
			printerrno("symlink");
			return EXIT_FAILURE;
		}

		return EXIT_SUCCESS;
	}

	if (!realpath(s, rs)) {
		printerrno("realpath");
		return EXIT_FAILURE;
	}

	if ((sfd = open(rs, O_RDONLY)) == -1) {
		printerrno("open");
		return EXIT_FAILURE;
	}

	strncpy(dc, d, PATH_MAX);
	dn = dirname(dc);
	if (mkdirrecursive(dn)) return EXIT_FAILURE;

	if (fileexists(d) && remove(d)) {
		printerrno("remove");
		return EXIT_FAILURE;
	}

	if (direxists(d) && rmdirrecursive(d)) return EXIT_FAILURE;

	if ((dfd = open(d, O_WRONLY | O_CREAT | O_TRUNC, 0700)) == -1) {
		close(sfd);
		printerrno("open");
		return EXIT_FAILURE;
	}

	while ((b = read(sfd, buf, sizeof(buf))) > 0) {
		write(dfd, buf, b);
	}

	close(sfd);
	close(dfd);

	return EXIT_SUCCESS;
}

int
createtmpdir(char dir[TMPFILE_SIZE])
{
	char log[PATH_MAX], src[PATH_MAX];
	int logfd;
	struct PathNode *newtmpd;

	if (mkdir("/tmp", 0700) == -1 && errno != EEXIST) {
		printerrno("mkdir");
		return EXIT_FAILURE;
	}

	strncpy(dir, TMPFILE, TMPFILE_SIZE);
	if (!mkdtemp(dir)) {
		printerrno("mkdtemp");
		return EXIT_FAILURE;
	}

	strncat(log, dir,    sizeof(log) - strlen(log) - 1);
	strncat(log, "/log", sizeof(log) - strlen(log) - 1);

	if ((logfd = open(log, O_WRONLY | O_CREAT | O_TRUNC, 0700)) == -1) {
		printerrno("open");
		return EXIT_FAILURE;
	}
	close(logfd);

	strncat(src, dir,    sizeof(src) - strlen(src) - 1);
	strncat(src, "/src", sizeof(src) - strlen(src) - 1);

	if (mkdir(src, 0700) == -1 && errno != EEXIST) {
		printerrno("mkdir");
		return EXIT_FAILURE;
	}

	if (!(newtmpd = malloc(sizeof(struct PathNode)))) {
		printerrno("malloc");
		return EXIT_FAILURE;
	}
	strncpy(newtmpd->p, dir, PATH_MAX);
	newtmpd->n = tmpdirhead;
	tmpdirhead = newtmpd;

	return EXIT_SUCCESS;
}

unsigned int
direxists(const char f[PATH_MAX])
{
	struct stat buf;
	if (lstat(f, &buf)) return 0;
	if (S_ISDIR(buf.st_mode)) return 1;
	return 0;
}

int
expandtilde(const char f[PATH_MAX], char ef[PATH_MAX])
{
	const char *home;

	if (f[0] != '~') {
		strncpy(ef, f, PATH_MAX);
		return EXIT_SUCCESS;
	}

	if (!(home = getenv("HOME"))) {
		printferr("Cannot expand tilde since HOME is undefined");
		return EXIT_FAILURE;
	}

	strncpy(ef, home, PATH_MAX);
	strncat(ef, f + 1, PATH_MAX - strlen(home)); /* skip ~ */

	return EXIT_SUCCESS;
}

int
fetchfile(char url[PATH_MAX], const char f[PATH_MAX])
{
	struct request_options o = { 0 };
	struct response *r;
	struct url u;
	char ua[NAME_MAX], cf[PATH_MAX];

	printf("\r\033[K- Downloading %s", url);
	fflush(stdout);

	strncat(ua, PROJECT_NAME, sizeof(ua) - strlen(ua) - 1);
	strncat(ua, "/",          sizeof(ua) - strlen(ua) - 1);
	strncat(ua, VERSION,      sizeof(ua) - strlen(ua) - 1);

	o.data_callback = (requests_user_cb_t)requestscallback;
	o.http_version = 0;
	o.user_data = &url;

	header_add(&o.header, "User-Agent", ua);

	u = resolve_url(url);
	o.url = &u;

	strncpy(cf, f, PATH_MAX);

	r = requests_get_file(NULL, cf, &o);

	if (!r) {
		printferr("Failed to fetch %s", url);
		free_url(o.url);
		requests_free_tls_context();
		return EXIT_FAILURE;
	}

	if (r->status_code >= 400) {
		printferr("Response code of %s is %u", url, r->status_code);
		free_url(o.url);
		requests_free_tls_context();
		return EXIT_FAILURE;
	}

	while (r->status_code > 300 && r->status_code < 307) {
		char *newloc = header_get_value(&r->header, "Location");

		if (!newloc) {
			printferr("Reponse code of %s is %u and no Location "
			          "header was provided", url, r->status_code);
			free_url(o.url);
			requests_free_tls_context();
			return EXIT_FAILURE;
		}
		free_url(o.url);
		*o.url = url_redirect(r->url, newloc);

		free_response(r);

		r = requests_get_file(NULL, cf, &o);

		if (!r) {
			printferr("Failed to fetch %s", url);
			free_url(o.url);
			requests_free_tls_context();
			return EXIT_FAILURE;
		}
	}

	free_url(o.url);
	requests_free_tls_context();

	return EXIT_SUCCESS;
}

unsigned int
fileexists(const char f[PATH_MAX])
{
	struct stat buf;
	return (!lstat(f, &buf) && !S_ISDIR(buf.st_mode));
}

int
getpackages(struct PackageNames *pkgs)
{
	size_t i;
	struct PathNode dhead, *d;
	const struct dirent *e;

	strncpy(dhead.p, repository, PATH_MAX);
	dhead.n = NULL;

	i = 0;
	for (d = &dhead; d; d = d->n) {
		DIR *dd;

		if (!(dd = opendir(d->p))) continue;

		while ((e = readdir(dd))) {
			int pe, subpe;
			char subd[PATH_MAX];
			char subpn[NAME_MAX];

			if (PACKAGES_MAX <= i + 1) {
				printferr("PACKAGES_MAX exceeded");
				return EXIT_FAILURE;
			}

			if (e->d_name[0] == '.') continue;

			if ((pe = packageexists(e->d_name)) == -1) {
				struct PathNode *dn;
				for (d = dhead.n; d; d = dn) {
					dn = d->n;
					free(d);
				}
				return EXIT_FAILURE;
			}

			if (pe) {
				strncpy(pkgs->a[i], e->d_name, NAME_MAX);
				i++;
				continue;
			}

			strncat(subd, d->p, sizeof(subd) - strlen(subd) - 1);
			strncat(subd, "/",  sizeof(subd) - strlen(subd) - 1);
			strncat(subd, e->d_name,
			        sizeof(subd) - strlen(subd) - 1);

			/* skip length of repository + / to get the package
			   name */
			strncpy(subpn, subd + strlen(repository) + 1,
			        NAME_MAX);

			subpe = packageexists(subpn);
			if (subpe == -1) {
				struct PathNode *dn;
				for (d = dhead.n; d; d = dn) {
					dn = d->n;
					free(d);
				}
				return EXIT_FAILURE;
			}

			if (subpe) {
				strncpy(pkgs->a[i], subpn, NAME_MAX);
				i++;
				continue;
			}
			
			if (direxists(subd)) {
				struct PathNode *new, *tail = d;

				if (!(new = malloc(sizeof(struct PathNode)))) {
					struct PathNode *dn;
					for (d = dhead.n; d; d = dn) {
						dn = d->n;
						free(d);
					}
					printerrno("malloc");
					return EXIT_FAILURE;
				}
				strncpy(new->p, subd, PATH_MAX);
				new->n = NULL;

				while (tail->n) tail = tail->n;
				tail->n = new;
			}
		}

		closedir(dd);
	}
	pkgs->l = i;

	if (sortpackages(pkgs)) return EXIT_FAILURE;

	return EXIT_SUCCESS;
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

int
installouts(struct Outs outs, const char sd[PATH_MAX], const char dd[PATH_MAX])
{
	size_t i;

	for (i = 0; i < outs.l; i++) {
		char s[PATH_MAX];

		strncat(s, sd,        sizeof(s) - strlen(s) - 1);
		strncat(s, outs.a[i], sizeof(s) - strlen(s) - 1);

		if (fileexists(s)) continue;
		if (direxists(s)) continue;

		printferr("Out file %s has not been installed",
		          outs.a[i]);
		return EXIT_FAILURE;
	}

	for (i = 0; i < outs.l; i++) {
		char s[PATH_MAX], d[PATH_MAX];

		strncat(s, sd,        sizeof(s) - strlen(s) - 1);
		strncat(s, outs.a[i], sizeof(s) - strlen(s) - 1);

		strncat(d, dd,        sizeof(d) - strlen(d) - 1);
		strncat(d, outs.a[i], sizeof(d) - strlen(d) - 1);

		if (fileexists(s)) {
			if (copyfile(s, d, 0)) return EXIT_FAILURE;
		} else if (direxists(s) && copydirrecursive(s, d)) {
			return EXIT_FAILURE;
		}
	}

	return EXIT_SUCCESS;
}

int
installpackage(struct Package p)
{
	char pdir[PATH_MAX], b[PATH_MAX], db[PATH_MAX], log[PATH_MAX],
	     src[PATH_MAX];
	const char *reltmpd;
	struct Sources srcs;
	struct Outs outs;
	pid_t pid;
	unsigned int nochr = packageisnochroot(p.pname);

	if (packageouts(p.pname, &outs)) return EXIT_FAILURE;

	if (!p.build) {
		if (installouts(outs, p.srcd, p.destd)) return EXIT_FAILURE;
		return EXIT_SUCCESS;
	}

	reltmpd = nochr ? p.srcd : "";

	strncat(pdir, repository, sizeof(pdir) - strlen(pdir) - 1);
	strncat(pdir, "/",        sizeof(pdir) - strlen(pdir) - 1);
	strncat(pdir, p.pname,    sizeof(pdir) - strlen(pdir) - 1);

	strncat(b, pdir,     sizeof(b) - strlen(b) - 1);
	strncat(b, "/build", sizeof(b) - strlen(b) - 1);

	strncat(db, p.srcd,       sizeof(db) - strlen(db) - 1);
	strncat(db, "/src/build", sizeof(db) - strlen(db) - 1);

	if (copyfile(b, db, 1)) return EXIT_FAILURE;

	if (packagesources(p.pname, &srcs)) return EXIT_FAILURE;
	if (srcs.l && retrievesources(srcs, pdir, p.srcd)) return EXIT_FAILURE;

	strncat(log, reltmpd, sizeof(log) - strlen(log) - 1);
	strncat(log, "/log",  sizeof(log) - strlen(log) - 1);

	strncat(src, reltmpd, sizeof(src) - strlen(src) - 1);
	strncat(src, "/src",  sizeof(src) - strlen(src) - 1);

	if ((pid = fork()) < 0) {
		printerrno("fork");
		return EXIT_FAILURE;
	}

	if (!pid) {
		char *cmd[] = { nochr ? db : "/src/build", NULL };
		int logf;

		if (!nochr && chroot(p.srcd)) {
			printerrno("chroot");
			exit(EXIT_FAILURE);
		}

		printf("\r\033[K- Building %s: logs can be viewed in %s/log",
		       p.pname, p.srcd);
		fflush(stdout);

		if ((logf = open(log, O_WRONLY, 0700)) == -1) {
			printerrno("fopen");
			exit(EXIT_FAILURE);
		}
		if (dup2(logf, STDOUT_FILENO) == -1) {
			printerrno("dup2");
			close(logf);
			exit(EXIT_FAILURE);
		}
		if (dup2(logf, STDERR_FILENO) == -1) {
			printerrno("dup2");
			close(logf);
			exit(EXIT_FAILURE);
		}
		close(logf);

		if (chdir(src)) {
			perror("chdir");
			exit(EXIT_FAILURE);
		}

		if (nochr) {
			const char *path = getenv("PATH");
			if (!path) {
				printferr("PATH is not defined");
				exit(EXIT_FAILURE);
			} else {
				char np[PATH_MAX];

				strncat(np, path,
				        sizeof(np) - strlen(np) - 1);
				strncat(np, ":",
				        sizeof(np) - strlen(np) - 1);
				strncat(np, p.srcd,
				        sizeof(np) - strlen(np) - 1);
				strncat(np, "/bin",
				        sizeof(np) - strlen(np) - 1);

				if (setenv("PATH", np, 1)) {
					perror("setenv");
					exit(EXIT_FAILURE);
				}
			}
		}

		if (!nochr && setenv("PATH", "/bin", 1)) {
			perror("setenv");
			exit(EXIT_FAILURE);
		}

		if (nochr && setenv("PREFIX", p.srcd, 1)) {
			perror("setenv");
			exit(EXIT_FAILURE);
		}

		if (execvp(cmd[0], cmd) == -1) {
			perror("execvp");
			exit(EXIT_FAILURE);
		}

		exit(EXIT_FAILURE);
	} else {
		int s;
		waitpid(pid, &s, 0);
		if (WIFEXITED(s)) {
			if (WEXITSTATUS(s)) {
				char logd[PATH_MAX];
				char logs[PATH_MAX];

				strncat(logs, p.srcd,
				        sizeof(logs) - strlen(logs) - 1);
				strncat(logs, "/log",
				        sizeof(logs) - strlen(logs) - 1);

				strncpy(logd, TMPFILE, TMPFILE_SIZE);

				if (mkstemp(logd) == -1) {
					printerrno("mkstemp");
					return EXIT_FAILURE;
				}

				if (copyfile(logs, logd, 1))
					return EXIT_FAILURE;

				printferr("Failed to build %s: see %s",
				          p.pname, logd);
				return EXIT_FAILURE;
			}
		}
	}

	printf("\r\033[K- Installing %s", p.pname);
	fflush(stdout);
	if (installouts(outs, p.srcd, p.destd)) return EXIT_FAILURE;
	if (!strncmp(p.destd, prefix, PATH_MAX))
		printf("\r\033[K+ Package %s installed\n", p.pname);

	return EXIT_SUCCESS;
}

int
mkdirrecursive(const char d[PATH_MAX])
{
	char *buf, *p = NULL;

	if (PATH_MAX <= strlen(d)) {
		printferr("PATH_MAX exceeded");
		return EXIT_FAILURE;
	}
	if (!(buf = malloc(sizeof(char) * PATH_MAX + 1))) {
		printerrno("malloc");
		return EXIT_FAILURE;
	}
	strncpy(buf, d, PATH_MAX);
	buf[PATH_MAX] = '\0';

	for (p = buf + 1; *p; p++) {
		if (*p == '/') {
			*p = '\0';
			if (mkdir(buf, 0700) && errno != EEXIST) {
				free(buf);
				printerrno("mkdir");
				return EXIT_FAILURE;
			}
			*p = '/';
		}
	}

	free(buf);

	if (mkdir(d, 0700) && errno != EEXIST) {
		printerrno("mkdir");
		return EXIT_FAILURE;
	}

	return EXIT_SUCCESS;
}

int
packagedepends(char pname[NAME_MAX], struct Depends *deps)
{
	size_t i;
	char f[PATH_MAX] = "";
	struct Lines l;

	strncat(f, repository, sizeof(f) - strlen(f) - 1);
	strncat(f, "/",        sizeof(f) - strlen(f) - 1);
	strncat(f, pname,      sizeof(f) - strlen(f) - 1);
	strncat(f, "/depends", sizeof(f) - strlen(f) - 1);

	if (readlines(f, &l)) return EXIT_FAILURE;

	for (i = 0; i < l.l; i++) {
		const char *tok;
		int nfields;

		if (i >= DEPENDS_MAX) {
			printferr("DEPENDS_MAX exceeded");
			return EXIT_FAILURE;
		}

		for (tok = strtok(l.a[i], " \t"), nfields = 0;
		     tok && nfields < 2;
		     tok = strtok(NULL, " \t"), nfields++) {
			switch (nfields) {
			case 0:
				if (NAME_MAX <= strlen(tok)) {
					printferr("NAME_MAX exceeded");
					return EXIT_FAILURE;
				}
				strncpy(deps->a[i].pname, tok, NAME_MAX);
				deps->a[i].pname[strlen(tok)] = '\0';
				break;
			case 1:
				if (strncmp(tok, "runtime", 7)) {
					printferr("The second field of %s in "
					          "%s's depends is something "
					          "different than 'runtime'",
					          deps->a[i].pname, pname);
					return EXIT_FAILURE;
				}
				deps->a[i].runtime = 1;
				break;
			}
		}

		if (nfields < 2) deps->a[i].runtime = 0;

		if (nfields < 1) {
			printferr("PROGRAM not present in one of %s's depends",
			          pname);
			return EXIT_FAILURE;
		}
	}
	deps->l = i;

	return EXIT_SUCCESS;
}

int
packageexists(const char pname[NAME_MAX])
{
	char bf[PATH_MAX] = "",
	     of[PATH_MAX] = "";

	strncat(bf, repository, sizeof(bf) - strlen(bf) - 1);
	strncat(bf, "/",        sizeof(bf) - strlen(bf) - 1);
	strncat(bf, pname,      sizeof(bf) - strlen(bf) - 1);
	strncat(bf, "/build",   sizeof(bf) - strlen(bf) - 1);

	strncat(of, repository, sizeof(of) - strlen(of) - 1);
	strncat(of, "/",        sizeof(of) - strlen(of) - 1);
	strncat(of, pname,      sizeof(of) - strlen(of) - 1);
	strncat(of, "/outs",    sizeof(of) - strlen(of) - 1);

	if (fileexists(bf) && fileexists(of)) return 1;

	return 0;
}

int
packageisinstalled(char pname[NAME_MAX], const char destd[PATH_MAX])
{
	struct Outs outs;
	size_t i;

	if (packageouts(pname, &outs)) return -1;

	for (i = 0; i < outs.l; i++) {
		char f[PATH_MAX];

		strncat(f, destd,     sizeof(f) - strlen(f) - 1);
		strncat(f, outs.a[i], sizeof(f) - strlen(f) - 1);

		if (!fileexists(f) && !direxists(f)) return 0;
	}

	return 1;
}

unsigned int
packageisnochroot(char pname[NAME_MAX])
{
	FILE *fp;
	char f[PATH_MAX] = "", buf[LINE_MAX];

	strncat(f, repository, sizeof(f) - strlen(f) - 1);
	strncat(f, "/",        sizeof(f) - strlen(f) - 1);
	strncat(f, pname,      sizeof(f) - strlen(f) - 1);
	strncat(f, "/outs",    sizeof(f) - strlen(f) - 1);

	fp = fopen(f, "r");
	if (!fp) return 0;

	if (!fgets(buf, sizeof(buf), fp)) return 0;

	buf[strcspn(buf, "\n")] = '\0';

	if (!strncmp(buf, "#no-chroot", LINE_MAX)) return 1;

	fclose(fp);
	return 0;
}

int
packageouts(char pname[NAME_MAX], struct Outs *outs)
{
	size_t i;
	struct Lines l;
	char f[PATH_MAX] = "";

	strncat(f, repository, sizeof(f) - strlen(f) - 1);
	strncat(f, "/",        sizeof(f) - strlen(f) - 1);
	strncat(f, pname,      sizeof(f) - strlen(f) - 1);
	strncat(f, "/outs",    sizeof(f) - strlen(f) - 1);

	if (readlines(f, &l)) return EXIT_FAILURE;

	for (i = 0; i < l.l; i++) {
		if (i >= OUTS_MAX) {
			printferr("OUTS_MAX exceeded");
			return EXIT_FAILURE;
		}
		if (l.a[i][0] != '/') {
			printferr("Non-absolute path found in %s's outs",
			    pname);
			return EXIT_FAILURE;
		}

		strncpy(outs->a[i], l.a[i], PATH_MAX);
	}
	outs->l = i;

	return EXIT_SUCCESS;
}

int
packagesources(char pname[NAME_MAX], struct Sources *srcs)
{
	size_t i;
	char f[PATH_MAX] = "";
	struct Lines l;

	strncat(f, repository, sizeof(f) - strlen(f) - 1);
	strncat(f, "/",        sizeof(f) - strlen(f) - 1);
	strncat(f, pname,      sizeof(f) - strlen(f) - 1);
	strncat(f, "/sources", sizeof(f) - strlen(f) - 1);

	if (readlines(f, &l)) return EXIT_FAILURE;

	for (i = 0; i < l.l; i++) {
		char *tok;
		int nfields;

		if (i >= SOURCES_MAX) {
			printferr("SOURCES_MAX exceeded");
			return EXIT_FAILURE;
		}

		for (tok = strtok(l.a[i], " \t"), nfields = 0;
		     tok && nfields < 3;
		     tok = strtok(NULL, " \t"), nfields++) {
			char sha256[2 * SHA256_DIGEST_LENGTH + 1];

			switch (nfields) {
			case 0:
				if (2 * SHA256_DIGEST_LENGTH != strlen(tok)) {
					printferr("SHA256 %s is not valid",
					          tok);
					return EXIT_FAILURE;
				}
				strncpy(sha256, tok, 2 * SHA256_DIGEST_LENGTH);
				sha256[2 * SHA256_DIGEST_LENGTH] = '\0';
				sha256chartouint8(sha256, srcs->a[i].sha256);
				break;
			case 1:
				if (PATH_MAX <= strlen(tok)) {
					printferr("PATH_MAX exceeded");
					return EXIT_FAILURE;
				}
				if (!relpathisvalid(tok) && !urlisvalid(tok)) {
					printferr("URL %s is not valid", tok);
					return EXIT_FAILURE;
				}
				strncpy(srcs->a[i].url, tok, PATH_MAX);
				srcs->a[i].url[strlen(tok)] = '\0';
				break;
			case 2:
				if (PATH_MAX <= strlen(tok)) {
					printferr("PATH_MAX exceeded");
					return EXIT_FAILURE;
				}
				if (!relpathisvalid(tok)) {
					printferr("RELPATH %s is not valid",
					          tok);
					return EXIT_FAILURE;
				}
				if (!strncmp(tok, "build", PATH_MAX)) {
					printferr("RELPATH cannot be 'build'");
					return EXIT_FAILURE;
				}
				if (!strncmp(tok, "build/", 6)) {
					printferr("RELPATH cannot be in the "
					          "'build' directory");
					return EXIT_FAILURE;
				}
				strncpy(srcs->a[i].relpath, tok, PATH_MAX);
				srcs->a[i].relpath[strlen(tok)] = '\0';
				break;
			}
		}

		if (nfields < 1) {
			printferr("SHA256 not present in one of %s's sources",
			    pname);
			return EXIT_FAILURE;
		} else if (nfields < 2) {
			printferr("URL not present in one of %s's sources",
			          pname);
			return EXIT_FAILURE;
		} else if (nfields < 3) {
			srcs->a[i].relpath[0] = '\0';
		}
	}
	srcs->l = i;

	return EXIT_SUCCESS;
}

void
printerrno(const char *s)
{
	printferr("%s: %s", s, strerror(errno));
}

void
printferr(const char *m, ...)
{
	va_list va;

	va_start(va, m);

	fprintf(stderr, "\r\033[K! ");
	vfprintf(stderr, m, va);
	putc('\n', stderr);
	fflush(stderr);

	va_end(va);
}

int
printinstalled(struct PackageNames pkgs)
{
	size_t i;

	for (i = 0; i < pkgs.l; i++) {
		int pii;
		if ((pii = packageisinstalled(pkgs.a[i], prefix)) == -1)
			return EXIT_FAILURE;
		if (pii)
			printf("%s\n", pkgs.a[i]);
	}

	return EXIT_SUCCESS;
}

void
printpackages(struct PackageNames pkgs)
{
	size_t i;
	for (i = 0; i < pkgs.l; i++) printf("%s\n", pkgs.a[i]);
}

int
readlines(const char f[PATH_MAX], struct Lines *l)
{
	size_t i;
	FILE *fp;
	char buf[LINE_MAX];

	fp = fopen(f, "r");
	if (!fp) {
		l->l = 0;
		return EXIT_SUCCESS;
	};

	i = 0;
	while (fgets(buf, sizeof(buf), fp)) {
		if (i >= LINES_MAX) {
			printferr("LINES_MAX exceeded");
			return EXIT_FAILURE;
		}
		if (buf[0] == '\n' || buf[0] == '#') continue;
		buf[strcspn(buf, "\n")] = '\0';
		strncpy(l->a[i], buf, LINE_MAX);
		i++;
	}
	l->l = i;

	fclose(fp);
	return EXIT_SUCCESS;
}

int
registerpackageinstall(struct Package *p)
{
	struct Depends *deps;
	struct Outs *outs;
	size_t i;
	int pe, pii;
	struct PackageNode *pn, *newpn, *tailpn;
	struct Package *newp;

	if ((pe = packageexists(p->pname)) == -1) return EXIT_FAILURE;
	if (!pe) {
		printferr("Package %s does not exist", p->pname);
		return EXIT_FAILURE;
	}

	if (!(outs = malloc(sizeof(struct Outs)))) {
		printerrno("malloc");
		return EXIT_FAILURE;
	}
	if (packageouts(p->pname, outs)) {
		free(outs);
		return EXIT_FAILURE;
	}
	if (!outs->l) {
		free(outs);
		printferr("Package %s has no outs", p->pname);
		return EXIT_FAILURE;
	}
	free(outs);

	/* cannot be reached by dependency since their installation is
	   checked before registration */
	if ((pii = packageisinstalled(p->pname, p->destd)) == -1)
		return EXIT_FAILURE;
	if (pii) {
		printf("+ Skipping %s since it is already installed\n",
		       p->pname);
		return EXIT_SUCCESS;
	}

	/* if already registered, register again to just copy from its srcd */
	for (pn = reqpkgshead; pn; pn = pn->n) {
		if (strncmp(p->pname, pn->p->pname, NAME_MAX)) continue;

		if (!(newpn = malloc(sizeof(struct PackageNode)))) {
			printerrno("malloc");
			return EXIT_FAILURE;
		}
		if (!(newp = malloc(sizeof(struct Package)))) {
			free(newpn);
			printerrno("malloc");
			return EXIT_FAILURE;
		}
		strncpy(newp->pname, p->pname, NAME_MAX);
		strncpy(newp->srcd, pn->p->srcd, PATH_MAX);
		strncpy(newp->destd, p->destd, PATH_MAX);
		newp->build = 0;

		newpn->p = newp;
		newpn->n = NULL;
		if (!reqpkgshead) {
			reqpkgshead = newpn;
			return EXIT_SUCCESS;
		}

		tailpn = reqpkgshead;
		while (tailpn->n) tailpn = tailpn->n;
		tailpn->n = newpn;

		return EXIT_SUCCESS;
	}


	if (p->build && packageisnochroot(p->pname)) {
		char yp;

		printf("+ Package %s will not use chroot, meaning it will "
		       "have no restrictions during the build\n", p->pname);
		printf("> Continue? (y/n) ");
		fflush(stdout);

		while ((yp = getchar()) != EOF) {
			if (yp == '\n') continue;
			if (yp == 'y' || yp == 'Y') break;
			printf("n\n");
			return EXIT_FAILURE;
		}

		printf("y\n");
	}

	if (!strlen(p->srcd)) {
		char tmpd[TMPFILE_SIZE];
		if (createtmpdir(tmpd)) return EXIT_FAILURE;
		strncpy(p->srcd, tmpd, PATH_MAX);
	}

	if (!(deps = malloc(sizeof(struct Depends)))) {
		printerrno("malloc");
		return EXIT_FAILURE;
	}
	if (packagedepends(p->pname, deps)) {
		free(deps);
		return EXIT_FAILURE;
	}
	for (i = 0; i < deps->l; i++) {
		int dpe, dpii;
		struct Outs *douts;
		struct Package *dp;
		char *ppname;

		/* if p->build == 0, only register runtime deps */
		if (!p->build && !deps->a[i].runtime) continue;

		if (!(ppname = malloc(sizeof(char) * PATH_MAX))) {
			printerrno("malloc");
			free(deps);
			return EXIT_FAILURE;
		}
		strncpy(ppname, deps->a[i].pname, PATH_MAX);
		if (!relpathisvalid(ppname)) {
			printferr("Invalid dependency %s", deps->a[i].pname);
			free(ppname);
			free(deps);
			return EXIT_FAILURE;
		}
		free(ppname);

		printf("+ Found dependency %s for %s\n",
		       deps->a[i].pname, p->pname);

		if ((dpe = packageexists(deps->a[i].pname)) == -1) {
			free(deps);
			return EXIT_FAILURE;
		}
		if (!dpe) {
			printferr("Dependency %s does not exist",
			          deps->a[i].pname);
			free(deps);
			return EXIT_FAILURE;
		}

		if (!(douts = malloc(sizeof(struct Outs)))) {
			free(deps);
			printerrno("malloc");
			return EXIT_FAILURE;
		}
		if (packageouts(deps->a[i].pname, douts)) {
			free(douts);
			free(deps);
			return EXIT_FAILURE;
		}
		if (!douts->l) {
			free(douts);
			printferr("Dependency %s has no outs",
			          deps->a[i].pname);
			free(deps);
			return EXIT_FAILURE;
		}
		free(douts);

		if ((dpii = packageisinstalled(deps->a[i].pname,
		                               prefix)) == -1) {
			free(deps);
			return EXIT_FAILURE;
		}

		if (!(dp = malloc(sizeof(struct Package)))) {
			printerrno("malloc");
			return EXIT_FAILURE;
		}

		/* always install dependency to p->srcd, regardless of it
		   being build or runtime */
		strncpy(dp->pname, deps->a[i].pname, NAME_MAX);
		strncpy(dp->destd, p->srcd, PATH_MAX);

		if (dpii) {
			/* if already installed to prefix, copy from prefix */
			strncpy(dp->srcd, prefix, PATH_MAX);
			dp->build = 0;
		} else {
			struct PackageNode *pn;
			unsigned int reg = 0;

			/* if already registered, register again to just copy
			   from its srcd */
			for (pn = reqpkgshead; pn; pn = pn->n) {
				if (strncmp(deps->a[i].pname, pn->p->pname,
				    NAME_MAX)) continue;

				strncpy(dp->srcd, pn->p->srcd, PATH_MAX);
				dp->build = 0;

				reg = 1;
				break;
			}

			/* if not installed or registered, build and install
			   it */
			if (!reg) {
				char dtmpd[TMPFILE_SIZE];

				if (createtmpdir(dtmpd)) {
					free(dp);
					return EXIT_FAILURE;
				}

				strncpy(dp->srcd, dtmpd, PATH_MAX);
				dp->build = 1;
			}
		}

		if (registerpackageinstall(dp)) {
			free(dp);
			free(deps);
			return EXIT_FAILURE;
		}
		free(dp);

		/* addionally, if runtime, copy from p->srcd to p->destd */
		if (deps->a[i].runtime) {
			struct Package *runp;

			if (!(runp = malloc(sizeof(struct Package)))) {
				printerrno("malloc");
				return EXIT_FAILURE;
			}

			strncpy(runp->pname, deps->a[i].pname, NAME_MAX);
			strncpy(runp->srcd, p->srcd, PATH_MAX);
			strncpy(runp->destd, p->destd, PATH_MAX);
			runp->build = 0;

			if (registerpackageinstall(runp)) {
				free(runp);
				free(deps);
				return EXIT_FAILURE;
			}
			free(runp);
		}
	}
	free(deps);

	if (!(newpn = malloc(sizeof(struct PackageNode)))) {
		printerrno("malloc");
		return EXIT_FAILURE;
	}
	if (!(newp = malloc(sizeof(struct Package)))) {
		free(newpn);
		printerrno("malloc");
		return EXIT_FAILURE;
	}
	memcpy(newp, p, sizeof(struct Package));

	newpn->p = newp;
	newpn->n = NULL;
	if (!reqpkgshead) {
		reqpkgshead = newpn;
		return EXIT_SUCCESS;
	}

	tailpn = reqpkgshead;
	while (tailpn->n) tailpn = tailpn->n;
	tailpn->n = newpn;

	return EXIT_SUCCESS;
}

int
registerpackageuninstall(struct Package *p, unsigned int rec)
{
	struct PackageNames *pkgs;
	struct Depends *deps;
	struct Outs *outs;
	size_t i;
	int pe, pii;
	struct PackageNode *newpn;
	struct Package *newp;

	if ((pe = packageexists(p->pname)) == -1) return EXIT_FAILURE;
	if (!pe) {
		printferr("Package %s does not exist", p->pname);
		return EXIT_FAILURE;
	}

	if (!(outs = malloc(sizeof(struct Outs)))) {
		printerrno("malloc");
		return EXIT_FAILURE;
	}
	if (packageouts(p->pname, outs)) return EXIT_FAILURE;
	if (!outs->l) {
		free(outs);
		printferr("Package %s has no outs", p->pname);
		return EXIT_FAILURE;
	}
	free(outs);

	if ((pii = packageisinstalled(p->pname, p->destd)) == -1)
		return EXIT_FAILURE;
	if (!pii) {
		printf("+ Skipping %s since it is not installed\n", p->pname);
		return EXIT_SUCCESS;
	}

	if (!(pkgs = malloc(sizeof(struct PackageNames)))) {
		printerrno("malloc");
		return EXIT_FAILURE;
	}
	if (getpackages(pkgs)) {
		free(pkgs);
		tcsetattr(STDIN_FILENO, TCSANOW, &oldt);
		return EXIT_FAILURE;
	}
	for (i = 0; i < pkgs->l; i++) {
		size_t j;
		int pkgsii;
		struct Depends *pdeps;
		struct PackageNode *pn = NULL;

		if (!strncmp(pkgs->a[i], p->pname, NAME_MAX)) continue;

		/* skip if pkg is registered for uninstall */
		for (pn = reqpkgshead; pn; pn = pn->n) {
			if (!strncmp(pn->p->pname, pkgs->a[i], NAME_MAX))
				break;
		}
		if (pn) continue; /* if for loop broke */

		if ((pkgsii = packageisinstalled(pkgs->a[i],
		                                 p->destd)) == -1) {
			free(pkgs);
			return EXIT_FAILURE;
		}
		if (!pkgsii) continue;

		if (!(pdeps = malloc(sizeof(struct Depends)))) {
			printerrno("malloc");
			return EXIT_FAILURE;
		}
		if (packagedepends(pkgs->a[i], pdeps)) {
			free(pdeps);
			free(pkgs);
			return EXIT_FAILURE;
		}
		for (j = 0; j < pdeps->l; j++) {
			if (strncmp(pdeps->a[j].pname, p->pname, NAME_MAX))
				continue;
			if (!pdeps->a[j].runtime) continue;

			printf("+ Skipping %s since %s depends on it\n",
			       p->pname, pkgs->a[i]);

			free(pdeps);
			free(pkgs);
			return EXIT_SUCCESS;
		}
		free(pdeps);
	}
	free(pkgs);

	if (!(newpn = malloc(sizeof(struct PackageNode)))) {
		printerrno("malloc");
		return EXIT_FAILURE;
	}
	if (!(newp = malloc(sizeof(struct Package)))) {
		free(newpn);
		printerrno("malloc");
		return EXIT_FAILURE;
	}
	memcpy(newp, p, sizeof(struct Package));

	newpn->p = newp;
	newpn->n = NULL;
	if (!reqpkgshead) {
		reqpkgshead = newpn;
	} else {
		struct PackageNode *tailpn;
		tailpn = reqpkgshead;
		while (tailpn->n) tailpn = tailpn->n;
		tailpn->n = newpn;
	}

	if (!rec) return EXIT_SUCCESS;

	if (!(deps = malloc(sizeof(struct Depends)))) {
		printerrno("malloc");
		return EXIT_FAILURE;
	}
	if (packagedepends(p->pname, deps)) {
		free(deps);
		return EXIT_FAILURE;
	}
	for (i = 0; i < deps->l; i++) {
		struct Package *newp;

		if (!deps->a[i].runtime) continue;

		printf("+ Found dependency %s for %s\n",
		       deps->a[i].pname, p->pname);

		if (!(newp = malloc(sizeof(struct Package)))) {
			printerrno("malloc");
			return EXIT_FAILURE;
		}

		strncpy(newp->pname, deps->a[i].pname, NAME_MAX);
		strncpy(newp->destd, p->destd, PATH_MAX);

		if (registerpackageuninstall(newp, rec)) {
			free(newp);
			free(deps);
			return EXIT_FAILURE;
		}
		free(newp);
	}
	free(deps);

	return EXIT_SUCCESS;
}

unsigned int
relpathisvalid(char relpath[PATH_MAX])
{
	return (!strstr(relpath, "..")
	     && !strstr(relpath, ":")
	     && !strstr(relpath, "//")
	     && relpath[0] != '/'
	     && strncmp(relpath, "./", 2)
	     && relpath[0] != '\0'
	     && relpath[strlen(relpath) - 1] != '/');
}

void
requestscallback(struct download_state* s, char *p[PATH_MAX])
{
	const int bl = 20;
	uint64_t rtot = s->content_length - s->bytes_left;
	double pr = (double)rtot / (double)s->content_length;
	int bfull = pr * bl, i,
	    bemp = (1.0f - pr) * bl;

	printf("\r\033[K- Downloading %s: [", *p);

	for (i = 0; i < bfull - 1; i++) putchar('=');
	if (bfull < bl && bfull >= 1) putchar('>');
	for (i = 0; i < bemp; i++) putchar(' ');

	printf("] %.2f%%", pr * 100.0f);
	fflush(stdout);
}

int
rmdirrecursive(const char d[PATH_MAX])
{
	struct dirent *e;
	DIR *dp;

	if (!(dp = opendir(d))) return EXIT_SUCCESS;

	while ((e = readdir(dp))) {
		char *f;
		size_t fs;

		if (!strcmp(e->d_name, ".") || !strcmp(e->d_name, ".."))
			continue;

		fs = strlen(d) + strlen("/") + strlen(e->d_name) + 1;
		if (!(f = malloc(fs))) {
			closedir(dp);
			printerrno("malloc");
			return EXIT_FAILURE;
		}
		strncat(f, d,         fs - strlen(f) - 1);
		strncat(f, "/",       fs - strlen(f) - 1);
		strncat(f, e->d_name, fs - strlen(f) - 1);

		if (direxists(f)) {
			if (rmdirrecursive(f)) {
				free(f);
				closedir(dp);
				return EXIT_FAILURE;
			}
		} else if (remove(f)) {
			free(f);
			closedir(dp);
			printerrno("remove");
			return EXIT_FAILURE;
		}

		free(f);
	}

	closedir(dp);

	if (rmdir(d)) {
		printerrno("rmdir");
		return EXIT_FAILURE;
	}

	return EXIT_SUCCESS;
}

int
retrievesources(struct Sources srcs, const char pdir[PATH_MAX],
                const char tmpd[PATH_MAX])
{
	size_t i;

	for (i = 0; i < srcs.l; i++) {
		const char *b = basename(srcs.a[i].url);

		if (!strncmp(b, "build", PATH_MAX)
		 && !strlen(srcs.a[i].relpath)) {
			printferr("Source file %s is named 'build': add a "
			          "RELPATH field", srcs.a[i].url);
			return EXIT_FAILURE;
		}

		if (urlisvalid(srcs.a[i].url)) {
			char df[PATH_MAX];
			uint8_t h[SHA256_DIGEST_LENGTH];

			strncat(df, tmpd,    sizeof(df) - strlen(df) - 1);
			strncat(df, "/src/", sizeof(df) - strlen(df) - 1);
			strncat(df, b,       sizeof(df) - strlen(df) - 1);

			if (fetchfile(srcs.a[i].url, df)) return EXIT_FAILURE;

			printf("\r\033[K- Computing the hash of %s",
			       srcs.a[i].url);
			fflush(stdout);
			if (sha256hash(df, h)) return EXIT_FAILURE;
			printf("\r\033[K");
			fflush(stdout);
			if (memcmp(h,
			           srcs.a[i].sha256,
			           SHA256_DIGEST_LENGTH)) {
				char eh[2 * SHA256_DIGEST_LENGTH + 1],
				     gh[2 * SHA256_DIGEST_LENGTH + 1];

				sha256uint8tochar(h, eh);
				sha256uint8tochar(srcs.a[i].sha256, gh);

				printferr("Hash of %s does not match:",
				          srcs.a[i].url);
				printferr("  Expected: %s", eh);
				printferr("  Got:      %s", gh);

				return EXIT_FAILURE;
			}
		} else if (relpathisvalid(srcs.a[i].url)) {
			char sf[PATH_MAX], df[PATH_MAX];
			uint8_t h[SHA256_DIGEST_LENGTH];

			strncat(sf, pdir, sizeof(sf) - strlen(sf) - 1);
			strncat(sf, "/",  sizeof(sf) - strlen(sf) - 1);
			strncat(sf, srcs.a[i].url,
			        sizeof(sf) - strlen(sf) - 1);

			strncat(df, tmpd,    sizeof(df) - strlen(df) - 1);
			strncat(df, "/src/", sizeof(df) - strlen(df) - 1);
			strncat(df, b,       sizeof(df) - strlen(df) - 1);

			if (!fileexists(sf)) {
				printferr("URL %s does not exist",
				          srcs.a[i].url);
				return EXIT_FAILURE;
			}

			printf("\r\033[K- Computing the hash of %s",
			       srcs.a[i].url);
			fflush(stdout);
			if (sha256hash(sf, h)) return EXIT_FAILURE;
			printf("\r\033[K");
			fflush(stdout);
			if (memcmp(h, srcs.a[i].sha256,
			           SHA256_DIGEST_LENGTH)) {
				char eh[2 * SHA256_DIGEST_LENGTH + 1],
				     gh[2 * SHA256_DIGEST_LENGTH + 1];

				sha256uint8tochar(h, eh);
				sha256uint8tochar(srcs.a[i].sha256, gh);

				printferr("Hash of %s does not match:",
				          srcs.a[i].url);
				printferr("  Expected: %s", eh);
				printferr("  Got:      %s", gh);

				return EXIT_FAILURE;
			}
			if (copyfile(sf, df, 1)) return EXIT_FAILURE;
		}

		if (strlen(srcs.a[i].relpath)) {
			char sf[PATH_MAX], df[PATH_MAX], mvd[PATH_MAX],
			     dc[PATH_MAX], *c, buf[PATH_MAX];
			size_t cl = 0;
			const char *dn;

			strncpy(dc, srcs.a[i].relpath, PATH_MAX);
			dn = dirname(dc);

			strncat(sf, tmpd,    sizeof(sf) - strlen(sf) - 1);
			strncat(sf, "/src/", sizeof(sf) - strlen(sf) - 1);
			strncat(sf, b,       sizeof(sf) - strlen(sf) - 1);

			strncat(df, tmpd,    sizeof(df) - strlen(df) - 1);
			strncat(df, "/src/", sizeof(df) - strlen(df) - 1);
			strncat(df, srcs.a[i].relpath,
			        sizeof(df) - strlen(df) - 1);

			if (direxists(df)) {
				printferr("RELPATH %s already exists and is a "
				          "directory", srcs.a[i].relpath);
				return EXIT_FAILURE;
			}

			for (c = df; *c; c++) {
				char f[PATH_MAX];
				buf[cl++] = *c;

				if (*c != '/') continue;

				buf[cl] = '\0';

				/* remove trailing slash */
				strncpy(f, buf, strlen(buf) - 1);
				f[strlen(buf) - 1] = '\0';

				if (!strlen(buf)) continue;
				if (!strncmp(f, df, PATH_MAX)) continue;

				if (!fileexists(f)) continue;

				printferr("One of the components of RELPATH "
				          "%s already exists",
				          srcs.a[i].relpath);
				return EXIT_FAILURE;
			}

			strncat(mvd, tmpd,    sizeof(mvd) - strlen(mvd) - 1);
			strncat(mvd, "/src/", sizeof(mvd) - strlen(mvd) - 1);
			strncat(mvd, dn,      sizeof(mvd) - strlen(mvd) - 1);

			if (mkdirrecursive(mvd)) return EXIT_FAILURE;

			if (rename(sf, df)) {
				printerrno("rename");
				return EXIT_FAILURE;
			}
		}
	}

	return EXIT_SUCCESS;
}

void
sha256chartouint8(const char c[2 * SHA256_DIGEST_LENGTH + 1],
                  uint8_t u[SHA256_DIGEST_LENGTH])
{
	int i;
	for (i = 0; i < SHA256_DIGEST_LENGTH; i++)
		sscanf(c + i * 2, "%2hhx", &u[i]);
}

int
sha256hash(const char f[PATH_MAX], uint8_t h[SHA256_DIGEST_LENGTH])
{
	unsigned char buf[4096];
	size_t br;
	struct sha256 ctx;
	FILE *ff;

	sha256_init(&ctx);

	if (!(ff = fopen(f, "rb"))) {
		printerrno("fopen");
		return EXIT_FAILURE;
	}

	while ((br = fread(buf, 1, sizeof(buf), ff)) > 0)
		sha256_update(&ctx, buf, br);

	if (ferror(ff)) {
		fclose(ff);
		printerrno("ferror");
		return EXIT_FAILURE;
	}

	fclose(ff);
	sha256_sum(&ctx, h);

	return EXIT_SUCCESS;
}

void
sha256uint8tochar(const uint8_t u[SHA256_DIGEST_LENGTH],
                  char c[2 * SHA256_DIGEST_LENGTH + 1])
{
	int i;
	for (i = 0; i < SHA256_DIGEST_LENGTH; i++)
		snprintf(&c[i * 2], 3, "%02x", u[i]);
	c[2 * SHA256_DIGEST_LENGTH] = '\0';
}

void
sigexit()
{
	cleanup();
	printferr("Interrupted");
	tcsetattr(STDIN_FILENO, TCSANOW, &oldt);
	exit(EXIT_FAILURE);
}

int
sortpackages(struct PackageNames *pkgs)
{
	char **a;
	size_t i;
	struct PackageNames *res;

	if (!pkgs->l) return EXIT_SUCCESS;

	if (!(a = malloc(sizeof(char *) * pkgs->l))) {
		printerrno("malloc");
		return EXIT_FAILURE;
	}

	for (i = 0; i < pkgs->l; i++) a[i] = pkgs->a[i];

	qsort(a, pkgs->l, sizeof(char *),
	      (int (*)(const void *, const void *))pnamecmp);

	if (!(res = malloc(sizeof(struct PackageNames)))) {
		free(a);
		printerrno("malloc");
		return EXIT_FAILURE;
	}
	res->l = pkgs->l;

	for (i = 0; i < pkgs->l; i++) strncpy(res->a[i], a[i], NAME_MAX);
	free(a);

	memcpy(pkgs, res, sizeof(struct PackageNames));
	free(res);

	return EXIT_SUCCESS;
}

int
uninstallpackage(struct Package p)
{
	struct Outs outs;
	size_t i;

	if (packageouts(p.pname, &outs)) return EXIT_FAILURE;

	printf("\r\033[K- Uninstalling %s", p.pname);
	fflush(stdout);
	for (i = 0; i < outs.l; i++) {
		char f[PATH_MAX];

		strncat(f, p.destd,   sizeof(f) - strlen(f) - 1);
		strncat(f, outs.a[i], sizeof(f) - strlen(f) - 1);

		if (fileexists(f)) {
			if (remove(f)) {
				printerrno("remove");
				return EXIT_FAILURE;
			}
		} else if (direxists(f) && rmdirrecursive(f)) {
			return EXIT_FAILURE;
		}
	}
	printf("\r\033[K+ Package %s uninstalled\n", p.pname);

	return EXIT_SUCCESS;
}

unsigned int
urlisvalid(const char url[PATH_MAX])
{
	return (!strncmp(url, "http://", 7)
	     || !strncmp(url, "https://", 8));
}

void
usage(void)
{
	fprintf(stderr, "Usage: %s -a [-s repo]\n"
	                "       %s -i [-s repo] [-p prefix] package ...\n"
	                "       %s -l [-s repo] [-p prefix]\n"
	                "       %s -u [-s repo] [-p prefix] [-r] package ...\n",
	                argv0, argv0, argv0, argv0);
	cleanup();
	exit(EXIT_FAILURE);
}

int
main(int argc, char *argv[])
{
	int aflag = 0,
	    iflag = 0,
	    lflag = 0,
	    pflag = 0,
	    rflag = 0,
	    uflag = 0;
	char gprefix[PATH_MAX] = DEFAULT_PREFIX,
	     grepository[PATH_MAX] = PACKAGE_REPOSITORY,
	     expprefix[PATH_MAX],
	     exprepository[PATH_MAX];
	struct termios newt;
	struct PackageNode *pn;

	if (getuid()) {
		fprintf(stderr, "%s: Superuser privileges are required\n",
		        argv[0]);
		cleanup();
		return EXIT_FAILURE;
	}

	ARGBEGIN {
	case 'a':
		aflag = 1;
		break;
	case 'i':
		iflag = 1;
		break;
	case 'l':
		lflag = 1;
		break;
	case 'p':
		pflag = 1;
		strncpy(gprefix, EARGF(usage()), PATH_MAX);
		break;
	case 'r':
		rflag = 1;
		break;
	case 's':
		strncpy(grepository, EARGF(usage()), PATH_MAX);
		break;
	case 'u':
		uflag = 1;
		break;
	default:
		usage();
	} ARGEND

	if ((lflag || aflag) && argc)
		usage();

	if (!(lflag || aflag) && !argc)
		usage();

	if (iflag + lflag + uflag + aflag != 1)
		usage();

	if (rflag && !uflag)
		usage();

	if (aflag && pflag)
		usage();

	tcgetattr(STDIN_FILENO, &oldt);
	newt = oldt;
	newt.c_lflag &= ~(ICANON | ECHO);
	tcsetattr(STDIN_FILENO, TCSANOW, &newt);

	handlesignals(sigexit);

	if (expandtilde(gprefix, expprefix)) {
		cleanup();
		return EXIT_FAILURE;
	}
	realpath(expprefix, prefix);

	if (expandtilde(grepository, exprepository)) {
		cleanup();
		return EXIT_FAILURE;
	}
	realpath(exprepository, repository);

	if (!strlen(prefix)) {
		cleanup();
		tcsetattr(STDIN_FILENO, TCSANOW, &oldt);
		printferr("Prefix is empty");
		return EXIT_FAILURE;
	}

	if (!strlen(repository)) {
		cleanup();
		tcsetattr(STDIN_FILENO, TCSANOW, &oldt);
		printferr("Repository path is empty");
		return EXIT_FAILURE;
	}

	if (!direxists(prefix)) {
		cleanup();
		tcsetattr(STDIN_FILENO, TCSANOW, &oldt);
		printferr("Prefix '%s' does not exist", prefix);
		return EXIT_FAILURE;
	}

	if (!direxists(repository)) {
		cleanup();
		tcsetattr(STDIN_FILENO, TCSANOW, &oldt);
		printferr("Repository directory '%s' does not exist", prefix);
		return EXIT_FAILURE;
	}

	if (prefix[strlen(prefix) - 1] == '/')
		prefix[strlen(prefix) - 1] = '\0';

	if (repository[strlen(repository) - 1] == '/')
		repository[strlen(repository) - 1] = '\0';

	if (lflag) {
		struct PackageNames pkgs;
		if (getpackages(&pkgs)) {
			cleanup();
			tcsetattr(STDIN_FILENO, TCSANOW, &oldt);
			return EXIT_FAILURE;
		}
		if (printinstalled(pkgs)) {
			cleanup();
			tcsetattr(STDIN_FILENO, TCSANOW, &oldt);
			return EXIT_FAILURE;
		}
	}

	if (aflag) {
		struct PackageNames pkgs;
		if (getpackages(&pkgs)) {
			cleanup();
			tcsetattr(STDIN_FILENO, TCSANOW, &oldt);
			return EXIT_FAILURE;
		}
		printpackages(pkgs);
	}

	/* will not be evaluated when either lflag or aflag is 1 */
	for (; *argv; argc--, argv++) {
		if (!relpathisvalid(*argv)) {
			printferr("Invalid package %s", *argv);
			return EXIT_FAILURE;
		}

		if (uflag) {
			struct Package *p;

			if (!(p = malloc(sizeof(struct Package)))) {
				printerrno("malloc");
				return EXIT_FAILURE;
			}

			strncpy(p->pname, *argv, NAME_MAX);
			strncpy(p->destd, prefix, PATH_MAX);

			if (registerpackageuninstall(p, rflag)) {
				free(p);
				cleanup();
				tcsetattr(STDIN_FILENO, TCSANOW, &oldt);
				return EXIT_FAILURE;
			}
			free(p);
		} else if (iflag) {
			struct Package *p;

			if (!(p = malloc(sizeof(struct Package)))) {
				printerrno("malloc");
				return EXIT_FAILURE;
			}

			strncpy(p->pname, *argv, NAME_MAX);
			strncpy(p->srcd, "", 1);
			strncpy(p->destd, prefix, PATH_MAX);
			p->build = 1;

			if (registerpackageinstall(p)) {
				free(p);
				cleanup();
				tcsetattr(STDIN_FILENO, TCSANOW, &oldt);
				return EXIT_FAILURE;
			}
			free(p);
		}
	}

	for (pn = reqpkgshead; pn; pn = pn->n) {
		if (iflag && installpackage(*pn->p)) {
			cleanup();
			tcsetattr(STDIN_FILENO, TCSANOW, &oldt);
			return EXIT_FAILURE;
		}
		if (uflag && uninstallpackage(*pn->p)) {
			cleanup();
			tcsetattr(STDIN_FILENO, TCSANOW, &oldt);
			return EXIT_FAILURE;
		}
	}

	cleanup();
	tcsetattr(STDIN_FILENO, TCSANOW, &oldt);
	return EXIT_SUCCESS;
}
