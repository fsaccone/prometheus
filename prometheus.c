/* See LICENSE file for copyright and license details. */

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <libgen.h>
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

#include <curl/curl.h>

#include "arg.h"
#include "config.h"
#include "sha256.h"

#define LINES_MAX     MAX(MAX(DEPENDS_MAX, OUTS_MAX), SOURCES_MAX)
#define MAX(a, b)     ((a) > (b) ? (a) : (b))
#define TMPDIR        "/tmp/prXXXXXX"
#define TMPDIR_SIZE   14

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
static int copydirrecursive(const char s[PATH_MAX], const char d[PATH_MAX]);
static int copyfile(const char s[PATH_MAX], const char d[PATH_MAX]);
static int createtmpdir(char dir[TMPDIR_SIZE]);
static int curlprogress(void *p, curl_off_t dltot, curl_off_t dlnow,
                        curl_off_t utot, curl_off_t upl);
static size_t curlwrite(void *d, size_t dl, size_t n, FILE *f);
static unsigned int direxists(const char f[PATH_MAX]);
static int expandtilde(const char f[PATH_MAX], char ef[PATH_MAX]);
static int fetchfile(const char url[PATH_MAX], const char f[PATH_MAX]);
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
static int packageouts(char pname[NAME_MAX], struct Outs *outs);
static int packagesources(char pname[NAME_MAX], struct Sources *srcs);
static void printerrno(const char *s);
static void printferr(const char *m, ...);
static int printinstalled(struct PackageNames pkgs);
static void printpackages(struct PackageNames pkgs);
static int readlines(const char f[PATH_MAX], struct Lines *l);
static int registerpackageinstall(struct Package p);
static unsigned int relpathisvalid(char relpath[PATH_MAX]);
static int rmdirrecursive(const char d[PATH_MAX]);
static int retrievesources(struct Sources srcs, const char pdir[PATH_MAX],
                           const char tmpd[PATH_MAX]);
static void sha256chartouint8(const char c[2 * SHA256_DIGEST_LENGTH + 1],
                              uint8_t u[SHA256_DIGEST_LENGTH]);
static int sha256hash(const char f[PATH_MAX], uint8_t h[SHA256_DIGEST_LENGTH]);
static void sha256uint8tochar(const uint8_t u[SHA256_DIGEST_LENGTH],
                              char c[2 * SHA256_DIGEST_LENGTH + 1]);
static void sigexit();
static int uninstallpackage(struct Package p);
static unsigned int urlisvalid(const char url[PATH_MAX]);
static void usage(void);

static struct termios oldt;
static struct PackageNode *pkgshead = NULL;
static char prefix[PATH_MAX];
static struct PathNode *tmpdirhead = NULL;

void
cleanup(void)
{
	struct PackageNode *pn, *pnn;
	struct PathNode *tmpd, *tmpdn;

	for (pn = pkgshead; pn; pn = pnn) {
		pnn = pn->n;
		free(pn->p);
		free(pn);
	}

	printf("\r\033[K\r");
	fflush(stdout);

	if (!tmpdirhead) return;

	printf("- Cleaning up\r");
	fflush(stdout);

	for (tmpd = tmpdirhead; tmpd; tmpd = tmpdn) {
		tmpdn = tmpd->n;
		(void)rmdirrecursive(tmpd->p);
		free(tmpd);
	}

	printf("\r\033[K\r");
	fflush(stdout);
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

		if (PATH_MAX <= strlen(s) + strlen("/") + strlen(e->d_name)) {
			printferr("PATH_MAX exceeded");
			return EXIT_FAILURE;
		}
		snprintf(sp, sizeof(sp), "%s/%s", s, e->d_name);

		if (PATH_MAX <= strlen(d) + strlen("/") + strlen(e->d_name)) {
			printferr("PATH_MAX exceeded");
			return EXIT_FAILURE;
		}
		snprintf(dp, sizeof(dp), "%s/%s", d, e->d_name);

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
		} else if (copyfile(sp, dp)) {
			return EXIT_FAILURE;
		}
	}

	return EXIT_SUCCESS;
}

int
copyfile(const char s[PATH_MAX], const char d[PATH_MAX])
{
	int sfd, dfd;
	char buf[1024], rs[PATH_MAX], dc[PATH_MAX];
	const char *dn;
	ssize_t b;

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
createtmpdir(char dir[TMPDIR_SIZE])
{
	char log[PATH_MAX], src[PATH_MAX];
	int logfd;
	struct PathNode *newtmpd;

	if (mkdir("/tmp", 0700) == -1 && errno != EEXIST) {
		printerrno("mkdir");
		return EXIT_FAILURE;
	}

	strncpy(dir, TMPDIR, TMPDIR_SIZE);
	if (!mkdtemp(dir)) {
		printerrno("mkdtemp");
		return EXIT_FAILURE;
	}

	if (PATH_MAX <= strlen(dir) + strlen("/prometheus.log")) {
		printferr("PATH_MAX exceeded");
		return EXIT_FAILURE;
	}
	snprintf(log, sizeof(log), "%s/prometheus.log", dir);
	if ((logfd = open(log, O_WRONLY | O_CREAT | O_TRUNC, 0700)) == -1) {
		printerrno("open");
		return EXIT_FAILURE;
	}
	close(logfd);

	if (PATH_MAX <= strlen(dir) + strlen("/src")) {
		printferr("PATH_MAX exceeded");
		return EXIT_FAILURE;
	}
	snprintf(src, sizeof(src), "%s/src", dir);
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

int
curlprogress(void *p, curl_off_t dltot, curl_off_t dlnow, curl_off_t utot,
             curl_off_t upl)
{
	printf("\r\033[K");

	if (dltot > 0) {
		const int bl = 20;
		double per = (double)dlnow / dltot * 100.0;
		int i, bpos = bl * dlnow / dltot;

		printf("- Downloading %s: [", (char *)p);
		for (i = 0; i < bl; i++) {
			if (i < bpos)
				printf("#");
			else
				printf("-");
		}
		printf("] %.2f%%\r", per);
	} else {
		printf("- Downloading %s: ?\r", (char *)p);
	}

	fflush(stdout);
	return 0;
}

size_t
curlwrite(void *d, size_t dl, size_t n, FILE *f)
{
	return fwrite(d, dl, n, f);
}

unsigned int
direxists(const char f[PATH_MAX])
{
	struct stat buf;
	if (stat(f, &buf)) return 0;
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
fetchfile(const char url[PATH_MAX], const char f[PATH_MAX])
{
	CURL *c;
	CURLcode cc;
	FILE *ff;
	long r;
	char ua[sizeof(PROJECT_NAME) + sizeof(VERSION)]; /* -2^\0 +/ +\0 */

	snprintf(ua, sizeof(ua), "%s/%s", PROJECT_NAME, VERSION);

	if (!(c = curl_easy_init())) {
		printferr("curl: Failed to initialize");
		return EXIT_FAILURE;
	}

	if (!(ff = fopen(f, "wb"))) {
		curl_easy_cleanup(c);
		printerrno("fopen");
		return EXIT_FAILURE;
	}

	curl_easy_setopt(c, CURLOPT_CONNECTTIMEOUT, 60L);
	curl_easy_setopt(c, CURLOPT_FOLLOWLOCATION, 1L);
	curl_easy_setopt(c, CURLOPT_FTP_RESPONSE_TIMEOUT, 60L);
	curl_easy_setopt(c, CURLOPT_FTP_USE_EPSV, 1L);
	curl_easy_setopt(c, CURLOPT_HTTP_VERSION, CURL_HTTP_VERSION_2_0);
	curl_easy_setopt(c, CURLOPT_NOPROGRESS, 0L);
	curl_easy_setopt(c, CURLOPT_SSL_VERIFYHOST, 2L);
	curl_easy_setopt(c, CURLOPT_SSL_VERIFYPEER, 1L);
	curl_easy_setopt(c, CURLOPT_TIMEOUT, 0L);
	curl_easy_setopt(c, CURLOPT_URL, url);
	curl_easy_setopt(c, CURLOPT_USE_SSL, CURLUSESSL_ALL);
	curl_easy_setopt(c, CURLOPT_USERAGENT, ua);
	curl_easy_setopt(c, CURLOPT_WRITEDATA, ff);
	curl_easy_setopt(c, CURLOPT_WRITEFUNCTION, curlwrite);
	curl_easy_setopt(c, CURLOPT_XFERINFODATA, url);
	curl_easy_setopt(c, CURLOPT_XFERINFOFUNCTION,
	                 (curl_xferinfo_callback)curlprogress);

	if ((cc = curl_easy_perform(c)) != CURLE_OK) {
		fclose(ff);
		curl_easy_cleanup(c);
		printferr("curl %s: %s", url, curl_easy_strerror(cc));
		return EXIT_FAILURE;
	}

	curl_easy_getinfo(c, CURLINFO_RESPONSE_CODE, &r);

	if (r >= 400) {
		printferr("curl %s: Response code %ld", url, r);
		fclose(ff);
		curl_easy_cleanup(c);
		return EXIT_FAILURE;
	}

	printf("\r\033[K+ Downloaded %s\n", url);
	fclose(ff);
	curl_easy_cleanup(c);

	return EXIT_SUCCESS;
}

unsigned int
fileexists(const char f[PATH_MAX])
{
	struct stat buf;
	return (!stat(f, &buf) && !S_ISDIR(buf.st_mode));
}

int
getpackages(struct PackageNames *pkgs)
{
	size_t i;
	DIR *d;
	const struct dirent *e;

	if (!(d = opendir(PACKAGE_REPOSITORY))) {
		pkgs->l = 0;
		return EXIT_SUCCESS;
	};

	i = 0;
	while ((e = readdir(d))) {
		int pe;

		if ((pe = packageexists(e->d_name)) == -1) return EXIT_FAILURE;

		if (e->d_name[0] == '.' || e->d_type != DT_DIR
		 || !strcmp(e->d_name, ".") || !strcmp(e->d_name, "..")
		 || !pe)
			continue;

		strncpy(pkgs->a[i], e->d_name, NAME_MAX);
		i++;
	}
	pkgs->l = i;

	closedir(d);
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
	int i;

	for (i = 0; i < outs.l; i++) {
		char s[PATH_MAX];

		if (PATH_MAX <= strlen(sd) + strlen(outs.a[i])) {
			printferr("PATH_MAX exceeded");
			return EXIT_FAILURE;
		}
		snprintf(s, sizeof(s), "%s%s", sd, outs.a[i]);

		if (fileexists(s)) continue;
		if (direxists(s)) continue;

		printferr("Out file %s has not been installed",
		          outs.a[i]);
		return EXIT_FAILURE;
	}

	for (i = 0; i < outs.l; i++) {
		char s[PATH_MAX], d[PATH_MAX];

		if (PATH_MAX <= strlen(sd) + strlen(outs.a[i])) {
			printferr("PATH_MAX exceeded");
			return EXIT_FAILURE;
		}
		snprintf(s, sizeof(s), "%s%s", sd, outs.a[i]);

		if (PATH_MAX <= strlen(dd) + strlen(outs.a[i])) {
			printferr("PATH_MAX exceeded");
			return EXIT_FAILURE;
		}
		snprintf(d, sizeof(d), "%s%s", dd, outs.a[i]);

		if (fileexists(s)) {
			if (copyfile(s, d)) return EXIT_FAILURE;
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
	unsigned int nochr = 0;

	if (packageouts(p.pname, &outs)) return EXIT_FAILURE;

	if (!p.build) {
		if (installouts(outs, p.srcd, p.destd)) return EXIT_FAILURE;
		return EXIT_SUCCESS;
	}

	if (!strncmp(p.pname, "nochroot-", 9)) nochr = 1;

	reltmpd = nochr ? p.srcd : "";

	if (PATH_MAX <= strlen(PACKAGE_REPOSITORY) + strlen("/")
	              + strlen(p.pname)) {
		printferr("PATH_MAX exceeded");
		return EXIT_FAILURE;
	}
	snprintf(pdir, sizeof(pdir), "%s/%s", PACKAGE_REPOSITORY, p.pname);

	if (PATH_MAX <= strlen(pdir) + strlen("/build")) {
		printferr("PATH_MAX exceeded");
		return EXIT_FAILURE;
	}
	snprintf(b, sizeof(b), "%s/build", pdir);

	if (PATH_MAX <= strlen(p.srcd) + strlen("/src/build")) {
		printferr("PATH_MAX exceeded");
		return EXIT_FAILURE;
	}
	snprintf(db, sizeof(db), "%s/src/build", p.srcd);

	if (copyfile(b, db)) return EXIT_FAILURE;

	if (packagesources(p.pname, &srcs)) return EXIT_FAILURE;
	if (srcs.l && retrievesources(srcs, pdir, p.srcd)) return EXIT_FAILURE;

	if (nochr && PATH_MAX <= strlen(p.srcd) + strlen("/prometheus.log")) {
		printferr("PATH_MAX exceeded");
		return EXIT_FAILURE;
	}
	snprintf(log, sizeof(log), "%s/prometheus.log", reltmpd);
	snprintf(src, sizeof(src), "%s/src", reltmpd);

	if ((pid = fork()) < 0) {
		fprintf(stderr, "\n");
		printerrno("fork");
		return EXIT_FAILURE;
	}

	if (!pid) {
		char *cmd[] = { nochr ? db : "/src/build", NULL };
		int logf;

		if (!nochr && chroot(p.srcd)) {
			fprintf(stderr, "\n");
			printerrno("chroot");
			exit(EXIT_FAILURE);
		}

		printf("- Building %s: logs can be viewed in "
		       "%s/prometheus.log\r", p.pname, p.srcd);
		fflush(stdout);

		if ((logf = open(log, O_WRONLY, 0700)) == -1) {
			fprintf(stderr, "\n");
			printerrno("fopen");
			exit(EXIT_FAILURE);
		}
		if (dup2(logf, STDOUT_FILENO) == -1) {
			fprintf(stderr, "\n");
			printerrno("dup2");
			close(logf);
			exit(EXIT_FAILURE);
		}
		if (dup2(logf, STDERR_FILENO) == -1) {
			fprintf(stderr, "\n");
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
				if (PATH_MAX <= strlen(path) + strlen(p.srcd)
				              + strlen("://bin")) {
					fprintf(stderr, "\n");
					printferr("PATH_MAX exceeded");
					exit(EXIT_FAILURE);
				}
				snprintf(np, sizeof(np), "%s:%s/bin",
				         path, p.srcd);
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

				if (PATH_MAX <= strlen(prefix)
				              + strlen("/prometheus.log")) {
					printferr("PATH_MAX exceeded");
					return EXIT_FAILURE;
				}
				snprintf(logd, sizeof(logd),
				         "%s/prometheus.log", prefix);

				if (copyfile(log, logd)) return EXIT_FAILURE;

				printf("\r\033[K\r");
				fflush(stdout);
				printferr("Failed to build %s: see %s",
				          p.pname, logd);
				return EXIT_FAILURE;
			}
		}
	}

	printf("\r\033[K- Installing %s\r", p.pname);
	fflush(stdout);
	if (installouts(outs, p.srcd, p.destd)) return EXIT_FAILURE;
	printf("\r\033[K+ Package %s installed\n", p.pname);

	return EXIT_SUCCESS;
}

int
mkdirrecursive(const char d[PATH_MAX])
{
	char buf[PATH_MAX], *p = NULL;

	if (PATH_MAX <= strlen(d)) {
		printferr("PATH_MAX exceeded");
		return EXIT_FAILURE;
	}
	strncpy(buf, d, sizeof(buf));
	buf[sizeof(buf) - 1] = '\0';

	for (p = buf + 1; *p; p++) {
		if (*p == '/') {
			*p = '\0';
			if (mkdir(buf, 0700) && errno != EEXIST) {
				printerrno("mkdir");
				return EXIT_FAILURE;
			}
			*p = '/';
		}
	}
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
	char f[PATH_MAX];
	struct Lines l;

	if (PATH_MAX <= strlen(PACKAGE_REPOSITORY) + strlen(pname)
	              + strlen("//depends")) {
		printferr("PATH_MAX exceeded");
		return EXIT_FAILURE;
	}
	snprintf(f, sizeof(f), "%s/%s/depends", PACKAGE_REPOSITORY, pname);
	if (readlines(f, &l)) return EXIT_FAILURE;

	for (i = 0; i < l.l; i++) {
		const char *tok;
		int nfields;

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
			default:
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
	char bf[PATH_MAX], of[PATH_MAX];

	if (PATH_MAX <= strlen(PACKAGE_REPOSITORY) + strlen(pname)
	              + strlen("//build")) { /* the longest one */
		printferr("PATH_MAX exceeded");
		return -1;
	}
	snprintf(bf, sizeof(bf), "%s/%s/build", PACKAGE_REPOSITORY, pname);
	snprintf(of, sizeof(of), "%s/%s/outs", PACKAGE_REPOSITORY, pname);

	if (fileexists(bf) && fileexists(of)) return 1;

	return 0;
}

int
packageisinstalled(char pname[NAME_MAX], const char destd[PATH_MAX])
{
	struct Outs outs;
	int i;

	if (packageouts(pname, &outs)) return -1;

	for (i = 0; i < outs.l; i++) {
		char f[PATH_MAX];
		if (PATH_MAX <= strlen(destd) + strlen(outs.a[i])) {
			printferr("PATH_MAX exceeded");
			return -1;
		}
		snprintf(f, sizeof(f), "%s%s", destd, outs.a[i]);
		if (!fileexists(f) && !direxists(f)) return 0;
	}

	return 1;
}

int
packageouts(char pname[NAME_MAX], struct Outs *outs)
{
	size_t i;
	struct Lines l;
	char f[PATH_MAX];

	if (PATH_MAX <= strlen(PACKAGE_REPOSITORY) + strlen(pname)
	              + strlen("//outs")) {
		printferr("PATH_MAX exceeded");
		return EXIT_FAILURE;
	}
	snprintf(f, sizeof(f), "%s/%s/outs", PACKAGE_REPOSITORY, pname);
	if (readlines(f, &l)) return EXIT_FAILURE;

	for (i = 0; i < l.l; i++) {
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
	char f[PATH_MAX];
	struct Lines l;

	if (PATH_MAX <= strlen(PACKAGE_REPOSITORY) + strlen(pname)
	              + strlen("//sources")) {
		printferr("PATH_MAX exceeded");
		return EXIT_FAILURE;
	}
	snprintf(f, sizeof(f), "%s/%s/sources", PACKAGE_REPOSITORY, pname);
	if (readlines(f, &l)) return EXIT_FAILURE;

	for (i = 0; i < l.l; i++) {
		char *tok;
		int nfields;

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
				strncpy(srcs->a[i].relpath, tok, PATH_MAX);
				srcs->a[i].relpath[strlen(tok)] = '\0';
				break;
			default:
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

	fprintf(stderr, "! ");
	vfprintf(stderr, m, va);
	putc('\n', stderr);

	va_end(va);
}

int
printinstalled(struct PackageNames pkgs)
{
	int i;

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
	int i;
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
	while (fgets(buf,sizeof(buf), fp) != NULL) {
		if (buf[0] == '\n' || buf[0] == '#') continue;
		buf[strcspn(buf, "\n")] = '\0';
		strncpy(l->a[i], buf, LINE_MAX);
		i++;
		if (i >= LINES_MAX) {
			printferr("LINES_MAX exceeded");
			return EXIT_FAILURE;
		}
	}
	l->l = i;

	fclose(fp);
	return EXIT_SUCCESS;
}

int
registerpackageinstall(struct Package p)
{
	struct Depends deps;
	struct Outs outs;
	int i, pe, pii;
	unsigned int nochr;
	struct PackageNode *newpn, *tailpn;
	struct Package *newp;

	if ((pe = packageexists(p.pname)) == -1) return EXIT_FAILURE;
	if (!pe) {
		printferr("Package %s does not exist", p.pname);
		return EXIT_FAILURE;
	}

	if (packageouts(p.pname, &outs)) return EXIT_FAILURE;
	if (!outs.l) {
		printferr("Package %s has no outs", p.pname);
		return EXIT_FAILURE;
	}

	/* cannot be reached by dependency since their installation is
	   checked before registration */
	if ((pii = packageisinstalled(p.pname, p.destd)) == -1)
		return EXIT_FAILURE;
	if (pii) {
		printf("+ Skipping %s since it is already installed\n",
		       p.pname);
		return EXIT_SUCCESS;
	}

	if (p.build && !strncmp(p.pname, "nochroot-", 9)) {
		char yp;

		printf("+ Package %s is a nochroot package: it will have full "
		       "access over your machine while building\n", p.pname);
		printf("> Continue? (y/n)\r");
		fflush(stdout);

		while ((yp = getchar()) != EOF) {
			if (yp == '\n') continue;
			if (yp == 'y' || yp == 'Y') break;
			printf("\r\033[K\r");
			fflush(stdout);
			return EXIT_FAILURE;
		}

		printf("\r\033[K\r");
		fflush(stdout);
	}

	if (!strlen(p.srcd)) {
		char tmpd[TMPDIR_SIZE];
		if (createtmpdir(tmpd)) return EXIT_FAILURE;
		strncpy(p.srcd, tmpd, PATH_MAX);
	}

	if (packagedepends(p.pname, &deps)) return EXIT_FAILURE;
	for (i = 0; i < deps.l; i++) {
		int dpe, dpii;
		struct Outs douts;
		struct Package dp, *dpp;

		/* if p.build == 0, only register runtime deps */
		if (!p.build && !deps.a[i].runtime) continue;

		printf("+ Found dependency %s for %s\n",
		       deps.a[i].pname, p.pname);

		if ((dpe = packageexists(deps.a[i].pname)) == -1)
			return EXIT_FAILURE;
		if (!dpe) {
			printferr("Dependency %s does not exist\n",
			          deps.a[i].pname);
			return EXIT_FAILURE;
		}

		if (packageouts(deps.a[i].pname, &douts))
			return EXIT_FAILURE;
		if (!douts.l) {
			printferr("Dependency %s has no outs\n",
			          deps.a[i].pname);
			return EXIT_FAILURE;
		}

		if ((dpii = packageisinstalled(deps.a[i].pname,
		                               prefix)) == -1)
			return EXIT_FAILURE;

		/* always install dependency to p.srcd, regardless of it
		   being build or runtime */
		strncpy(dp.pname, deps.a[i].pname, NAME_MAX);
		strncpy(dp.destd, p.srcd, PATH_MAX);

		if (dpii) {
			/* if already installed to prefix, copy from prefix */
			strncpy(dp.srcd, prefix, PATH_MAX);
			dp.build = 0;
		} else {
			struct PackageNode *pn;
			unsigned int reg = 0;

			/* if already registered, register again to just copy
			   from its srcd */
			for (pn = pkgshead; pn; pn = pn->n) {
				if (strncmp(deps.a[i].pname, pn->p->pname,
				    NAME_MAX)) continue;

				strncpy(dp.srcd, pn->p->srcd, PATH_MAX);
				dp.build = 0;

				reg = 1;
				break;
			}

			/* if not installed or registered, build and install
			   it */
			if (!reg) {
				char dtmpd[TMPDIR_SIZE];

				if (createtmpdir(dtmpd)) return EXIT_FAILURE;

				strncpy(dp.srcd, dtmpd, PATH_MAX);
				dp.build = 1;
			}
		}

		if (!(dpp = malloc(sizeof(struct Package)))) {
			printerrno("malloc");
			return EXIT_FAILURE;
		}
		memcpy(dpp, &dp, sizeof(struct Package));
		if (registerpackageinstall(*dpp)) {
			free(dpp);
			return EXIT_FAILURE;
		}
		free(dpp);

		/* addionally, if runtime, copy from p.srcd to p.destd */
		if (deps.a[i].runtime) {
			struct Package runp, *runpp;
			strncpy(runp.pname, deps.a[i].pname, NAME_MAX);
			strncpy(runp.srcd, p.srcd, PATH_MAX);
			strncpy(runp.destd, p.destd, PATH_MAX);
			runp.build = 0;

			if (!(runpp = malloc(sizeof(struct Package)))) {
				printerrno("malloc");
				return EXIT_FAILURE;
			}
			memcpy(runpp, &runp, sizeof(struct Package));
			if (registerpackageinstall(*runpp)) {
				free(runpp);
				return EXIT_FAILURE;
			}
			free(runpp);
		}
	}

	if (!(newpn = malloc(sizeof(struct PackageNode)))) {
		printerrno("malloc");
		return EXIT_FAILURE;
	}
	if (!(newp = malloc(sizeof(struct Package)))) {
		free(newpn);
		printerrno("malloc");
		return EXIT_FAILURE;
	}
	memcpy(newp, &p, sizeof(struct Package));

	newpn->p = newp;
	newpn->n = NULL;
	if (!pkgshead) {
		pkgshead = newpn;
		return EXIT_SUCCESS;
	}

	tailpn = pkgshead;
	while (tailpn->n) tailpn = tailpn->n;
	tailpn->n = newpn;

	return EXIT_SUCCESS;
}

int
registerpackageuninstall(struct Package p, unsigned int rec)
{
	struct PackageNames *pkgs;
	struct Depends deps;
	struct Outs outs;
	int i, pe, pii;
	struct PackageNode *newpn;
	struct Package *newp;

	if ((pe = packageexists(p.pname)) == -1) return EXIT_FAILURE;
	if (!pe) {
		printferr("Package %s does not exist", p.pname);
		return EXIT_FAILURE;
	}

	if (packageouts(p.pname, &outs)) return EXIT_FAILURE;
	if (!outs.l) {
		printferr("Package %s has no outs", p.pname);
		return EXIT_FAILURE;
	}

	if ((pii = packageisinstalled(p.pname, p.destd)) == -1)
		return EXIT_FAILURE;
	if (!pii) {
		printf("+ Skipping %s since it is not installed\n", p.pname);
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
		int pkgsii, j;
		struct Depends pdeps;

		if (!strncmp(pkgs->a[i], p.pname, NAME_MAX)) continue;

		if ((pkgsii = packageisinstalled(pkgs->a[i],
		                                 p.destd)) == -1) {
			free(pkgs);
			return EXIT_FAILURE;
		}
		if (!pkgsii) continue;

		if (packagedepends(pkgs->a[i], &pdeps)) {
			free(pkgs);
			return EXIT_FAILURE;
		}

		for (j = 0; j < pdeps.l; j++) {
			if (strncmp(pdeps.a[j].pname, p.pname, NAME_MAX))
				continue;
			if (!pdeps.a[j].runtime) continue;

			printf("+ Skipping %s since %s depends on it\n",
			       p.pname, pkgs->a[i]);

			free(pkgs);
			return EXIT_SUCCESS;
		}
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
	strncpy(newp->pname, p.pname, NAME_MAX);
	strncpy(newp->destd, p.destd, PATH_MAX);

	newpn->p = newp;
	newpn->n = NULL;
	if (!pkgshead) {
		pkgshead = newpn;
	} else {
		struct PackageNode *tailpn;
		tailpn = pkgshead;
		while (tailpn->n) tailpn = tailpn->n;
		tailpn->n = newpn;
	}

	if (!rec) return EXIT_SUCCESS;

	if (packagedepends(p.pname, &deps)) return EXIT_FAILURE;
	for (i = 0; i < deps.l; i++) {
		struct Package newp, *newpp;

		if (!deps.a[i].runtime) continue;

		printf("+ Found dependency %s for %s\n",
		       deps.a[i].pname, p.pname);

		strncpy(newp.pname, deps.a[i].pname, NAME_MAX);
		strncpy(newp.destd, p.destd, PATH_MAX);

		if (!(newpp = malloc(sizeof(struct Package)))) {
			printerrno("malloc");
			return EXIT_FAILURE;
		}
		memcpy(newpp, &newp, sizeof(struct Package));
		if (registerpackageuninstall(*newpp, rec)) {
			free(newpp);
			return EXIT_FAILURE;
		}
		free(newpp);
	}

	return EXIT_SUCCESS;
}

unsigned int
relpathisvalid(char relpath[PATH_MAX])
{
	return (!strstr(relpath, "..") && !strstr(relpath, ":")
	     && relpath[0] != '/' && relpath[0] != '.' && relpath[0] != '\0'
	     && relpath[strlen(relpath) - 1] != '/');
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
		if (PATH_MAX < fs) {
			closedir(dp);
			printferr("PATH_MAX exceeded");
			return EXIT_FAILURE;
		}
		if (!(f = malloc(fs))) {
			closedir(dp);
			printerrno("malloc");
			return EXIT_FAILURE;
		}
		snprintf(f, fs, "%s/%s", d, e->d_name);

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
	int i;

	for (i = 0; i < srcs.l; i++) {
		const char *b = basename(srcs.a[i].url);

		if (urlisvalid(srcs.a[i].url)) {
			char df[PATH_MAX];
			uint8_t h[SHA256_DIGEST_LENGTH];

			if (PATH_MAX <= strlen(tmpd) + strlen(b)
			              + strlen("/src/")) {
				printferr("PATH_MAX exceeded");
				return EXIT_FAILURE;
			}
			snprintf(df, sizeof(df), "%s/src/%s", tmpd, b);

			if (fetchfile(srcs.a[i].url, df)) return EXIT_FAILURE;

			if (sha256hash(df, h)) return EXIT_FAILURE;
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

			if (PATH_MAX <= strlen(pdir) + strlen("/")
			              + strlen(srcs.a[i].url)) {
				printferr("PATH_MAX exceeded");
				return EXIT_FAILURE;
			}
			snprintf(sf, sizeof(sf), "%s/%s", pdir, srcs.a[i].url);

			if (PATH_MAX <= strlen(tmpd) + strlen("/src/")
			              + strlen(b)) {
				printferr("PATH_MAX exceeded");
				return EXIT_FAILURE;
			}
			snprintf(df, sizeof(df), "%s/src/%s", tmpd, b);

			if (!fileexists(sf)) {
				printferr("URL %s does not exist",
				          srcs.a[i].url);
				return EXIT_FAILURE;
			}

			if (sha256hash(sf, h)) return EXIT_FAILURE;
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
			if (copyfile(sf, df)) return EXIT_FAILURE;
		}

		if (strlen(srcs.a[i].relpath)) {
			char sf[PATH_MAX], df[PATH_MAX], mvd[PATH_MAX],
			     dc[PATH_MAX], *tok, buf[PATH_MAX];
			const char *dn;

			strncpy(dc, srcs.a[i].relpath, PATH_MAX);
			dn = dirname(dc);

			if (PATH_MAX <= strlen(tmpd) + strlen("/src/")
			              + strlen(b)) {
				printferr("PATH_MAX exceeded");
				return EXIT_FAILURE;
			}
			snprintf(sf, sizeof(sf), "%s/src/%s", tmpd, b);

			if (PATH_MAX <= strlen(tmpd) + strlen("/src/")
			              + strlen(srcs.a[i].relpath)) {
				printferr("PATH_MAX exceeded");
				return EXIT_FAILURE;
			}
			snprintf(df, sizeof(df), "%s/src/%s",
			         tmpd, srcs.a[i].relpath);

			strncpy(buf, df, PATH_MAX);
			tok = strtok(buf + strlen(tmpd)
			                 + strlen("/src/"), "/");
			for (; tok; tok = strtok(NULL, "/")) {
				char f[PATH_MAX];
				snprintf(f, sizeof(f), "%s/src/%s", tmpd, tok);
				if (fileexists(f) /* any comp is not dir */
				 && strncmp(f, df, PATH_MAX)) {
					printferr("One of the components of "
					          "RELPATH %s already exists",
					          srcs.a[i].relpath);
					return EXIT_FAILURE;
				}
			}

			if (PATH_MAX <= strlen(tmpd) + strlen("/src/")
			              + strlen(dn)) {
				printferr("PATH_MAX exceeded");
				return EXIT_FAILURE;
			}
			snprintf(mvd, sizeof(mvd), "%s/src/%s", tmpd, dn);

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
	tcsetattr(STDIN_FILENO, TCSANOW, &oldt);
	exit(EXIT_FAILURE);
}

int
uninstallpackage(struct Package p)
{
	struct Outs outs;
	int i;

	if (packageouts(p.pname, &outs)) return EXIT_FAILURE;

	printf("- Uninstalling %s\r", p.pname);
	fflush(stdout);
	for (i = 0; i < outs.l; i++) {
		char f[PATH_MAX];

		if (PATH_MAX <= strlen(p.destd) + strlen(outs.a[i])) {
			fprintf(stderr, "\n");
			printferr("PATH_MAX exceeded");
			return EXIT_FAILURE;
		}
		snprintf(f, sizeof(f), "%s%s", p.destd, outs.a[i]);

		if (fileexists(f)) {
			if (remove(f)) {
				fprintf(stderr, "\n");
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
	     || !strncmp(url, "https://", 8)
	     || !strncmp(url, "ftp://", 6));
}

void
usage(void)
{
	fprintf(stderr, "Usage: %s -i [-p prefix] package ...\n"
	                "       %s -u [-p prefix] [-r] package ...\n"
	                "       %s -l [-p prefix]\n"
	                "       %s -a\n",
	                argv0, argv0, argv0, argv0);
	cleanup();
	exit(EXIT_FAILURE);
}

int
main(int argc, char *argv[])
{
	int install = 0,
	    uninstall = 0,
	    recuninstall = 0,
	    printinst = 0,
	    printall = 0,
	    prefixdef = 0;
	char gprefix[PATH_MAX] = DEFAULT_PREFIX, expprefix[PATH_MAX],
	     log[PATH_MAX];
	struct termios newt;
	struct PackageNode *pn;
	struct PathNode *tmpd;

	if (getuid()) {
		fprintf(stderr, "%s: Superuser privileges are required\n",
		        argv[0]);
		cleanup();
		return EXIT_FAILURE;
	}

	ARGBEGIN {
	case 'a':
		printall = 1;
		break;
	case 'i':
		install = 1;
		break;
	case 'l':
		printinst = 1;
		break;
	case 'p':
		strncpy(gprefix, EARGF(usage()), PATH_MAX);
		prefixdef = 1;
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

	if ((printinst || printall) && argc)
		usage();

	if (!(printinst || printall) && !argc)
		usage();

	if (install + printinst + uninstall + printall != 1)
		usage();

	if (recuninstall && !uninstall)
		usage();

	if (printall && prefixdef)
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

	if (!strlen(prefix)) {
		cleanup();
		tcsetattr(STDIN_FILENO, TCSANOW, &oldt);
		printferr("Prefix is empty");
		return EXIT_FAILURE;
	}

	if (strlen(prefix) > 1 && prefix[strlen(prefix) - 1] == '/')
		prefix[strlen(prefix) - 1] = '\0';

	if (!direxists(prefix)) {
		cleanup();
		tcsetattr(STDIN_FILENO, TCSANOW, &oldt);
		printferr("Prefix '%s' does not exist", prefix);
		return EXIT_FAILURE;
	}

	if (PATH_MAX <= strlen(prefix) + strlen("/prometheus.log")) {
		cleanup();
		tcsetattr(STDIN_FILENO, TCSANOW, &oldt);
		printferr("PATH_MAX exceeded");
		return EXIT_FAILURE;
	}
	snprintf(log, sizeof(log), "%s/prometheus.log", prefix);
	printf("- Cleaning up\r");
	if (fileexists(log) && remove(log)) {
		cleanup();
		tcsetattr(STDIN_FILENO, TCSANOW, &oldt);
		printerrno("remove");
		return EXIT_FAILURE;
	}
	printf("\r\033[K\r");

	if (printinst) {
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

	if (printall) {
		struct PackageNames pkgs;
		if (getpackages(&pkgs)) {
			cleanup();
			tcsetattr(STDIN_FILENO, TCSANOW, &oldt);
			return EXIT_FAILURE;
		}
		printpackages(pkgs);
	}

	/* will not be evaluated when either printinst or prinstall is 1 */
	for (; *argv; argc--, argv++) {
		if (uninstall) {
			struct Package p;

			strncpy(p.pname, *argv, NAME_MAX);
			strncpy(p.destd, prefix, PATH_MAX);

			if (registerpackageuninstall(p, recuninstall)) {
				cleanup();
				tcsetattr(STDIN_FILENO, TCSANOW, &oldt);
				return EXIT_FAILURE;
			}
		} else if (install) {
			struct Package p;

			strncpy(p.pname, *argv, NAME_MAX);
			strncpy(p.srcd, "", 1);
			strncpy(p.destd, prefix, PATH_MAX);
			p.build = 1;

			if (registerpackageinstall(p)) {
				cleanup();
				tcsetattr(STDIN_FILENO, TCSANOW, &oldt);
				return EXIT_FAILURE;
			}
		}
	}

	for (pn = pkgshead; pn; pn = pn->n) {
		if (install && installpackage(*pn->p)) {
			cleanup();
			tcsetattr(STDIN_FILENO, TCSANOW, &oldt);
			return EXIT_FAILURE;
		}
		if (uninstall && uninstallpackage(*pn->p)) {
			cleanup();
			tcsetattr(STDIN_FILENO, TCSANOW, &oldt);
			return EXIT_FAILURE;
		}
	}

	cleanup();
	tcsetattr(STDIN_FILENO, TCSANOW, &oldt);
	return EXIT_SUCCESS;
}
