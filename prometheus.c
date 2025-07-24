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
#include <unistd.h>

#include <curl/curl.h>

#include <lua.h>
#include <lualib.h>
#include <lauxlib.h>

#include "arg.h"
#include "config.h"
#include "lua.h"
#include "sha256.h"

#define DIE_MAX   1024
#define MAX(a, b) ((a) > (b) ? (a) : (b))
#define LINES_MAX MAX(MAX(DEPENDS_MAX, OUTS_MAX), SOURCES_MAX)

struct Depend {
	char pname[PROGRAM_MAX];
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

struct Packages {
	char a[PACKAGES_MAX][NAME_MAX];
	size_t l;
};

struct Outs {
	char a[OUTS_MAX][PATH_MAX];
	size_t l;
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

static int buildpackage(char *pname, const char *tmpd, unsigned int nochr);
static int copyfile(const char *s, const char *d);
static int createtmpdir(char *pname, char dir[PATH_MAX]);
static int curlprogress(void *p, curl_off_t dltot, curl_off_t dlnow,
                        curl_off_t utot, curl_off_t upl);
static size_t curlwrite(void *d, size_t dl, size_t n, FILE *f);
static unsigned int direxists(const char *f);
static int expandtilde(const char *f, char ef[PATH_MAX]);
static int fetchfile(const char *url, const char *f);
static unsigned int fileexists(const char *f);
static int followsymlink(const char *f, char ff[PATH_MAX]);
static int getpackages(struct Packages *pkgs);
static void handlesignals(void(*hdl)(int));
static int installpackage(char *pname, char *prefix, unsigned int y);
static int mkdirrecursive(const char *d);
static int packagedepends(char *pname, struct Depends *deps);
static int packageexists(char *pname);
static int packageisinstalled(char *pname, char *prefix);
static int packageouts(char *pname, struct Outs *outs);
static int packagesources(char *pname, struct Sources *srcs);
static void printferr(const char *m, ...);
static void printinstalled(char *prefix, struct Packages pkgs);
static void printpackages(struct Packages pkgs);
static int readlines(const char *f, struct Lines *l);
static void registerluautils(lua_State *luas);
static unsigned int relpathisvalid(char *relpath);
static int retrievesources(struct Sources srcs, const char *pdir,
                           const char *tmpd);
static void sha256chartouint8(char c[2 * SHA256_DIGEST_LENGTH + 1],
                              uint8_t u[SHA256_DIGEST_LENGTH]);
static int sha256hash(const char *f, uint8_t h[SHA256_DIGEST_LENGTH]);
static void sha256uint8tochar(uint8_t u[SHA256_DIGEST_LENGTH],
                              char c[2 * SHA256_DIGEST_LENGTH + 1]);
static void sigexit();
static int uninstallpackage(char *pname, char *prefix, unsigned int rec,
                            struct Packages pkgs);
static unsigned int urlisvalid(char *url);
static void usage(void);

int
buildpackage(char *pname, const char *tmpd, unsigned int nochr)
{
	char pdir[PATH_MAX], b[PATH_MAX], db[PATH_MAX], log[PATH_MAX],
	     src[PATH_MAX];
	const char *reltmpd = nochr ? tmpd : "";
	struct Sources srcs;
	pid_t pid;

	if (PATH_MAX <= strlen(PACKAGE_REPOSITORY) + strlen("/")
	              + strlen(pname)) {
		printferr("PATH_MAX exceeded");
		return EXIT_FAILURE;
	}
	snprintf(pdir, sizeof(pdir), "%s/%s", PACKAGE_REPOSITORY, pname);

	if (PATH_MAX <= strlen(pdir) + strlen("/build.lua")) {
		printferr("PATH_MAX exceeded");
		return EXIT_FAILURE;
	}
	snprintf(b, sizeof(b), "%s/build.lua", pdir);

	if (PATH_MAX <= strlen(tmpd) + strlen("/src/build.lua")) {
		printferr("PATH_MAX exceeded");
		return EXIT_FAILURE;
	}
	snprintf(db, sizeof(db), "%s/src/build.lua", tmpd);

	if (copyfile(b, db)) return EXIT_FAILURE;

	if (packagesources(pname, &srcs)) return EXIT_FAILURE;
	if (srcs.l) {
		printf("- Retrieving %s's sources\n", pname);
		if (retrievesources(srcs, pdir, tmpd)) return EXIT_FAILURE;
		printf("+ Retrieved %s's sources\n", pname);
	}

	if (nochr && PATH_MAX <= strlen(tmpd) + strlen("/prometheus.log")) {
		printferr("PATH_MAX exceeded");
		return EXIT_FAILURE;
	}
	snprintf(log, sizeof(log), "%s/prometheus.log", reltmpd);
	snprintf(src, sizeof(src), "%s/src", reltmpd);

	if ((pid = fork()) < 0) {
		perror("+ fork");
		return EXIT_FAILURE;
	}

	if (!pid) {
		lua_State *luas;
		int logf;

		if (!nochr && chroot(tmpd)) {
			perror("+ chroot");
			exit(EXIT_FAILURE);
		}

		printf("- Building %s\n", pname);

		if(!(luas = luaL_newstate())) {
			perror("+ luaL_newstate");
			exit(EXIT_FAILURE);
		}
		luaL_openlibs(luas);
		registerluautils(luas);

		if (!(logf = open(log, O_WRONLY, 0700))) {
			perror("+ fopen");
			exit(EXIT_FAILURE);
		}
		if (dup2(logf, STDOUT_FILENO) == -1) {
			perror("+ dup2");
			close(logf);
			exit(EXIT_FAILURE);
		}
		if (dup2(logf, STDERR_FILENO) == -1) {
			perror("+ dup2");
			close(logf);
			exit(EXIT_FAILURE);
		}
		close(logf);

		if (chdir(src)) {
			perror("+ chdir");
			exit(EXIT_FAILURE);
		}

		if (!nochr && setenv("PATH", "/bin", 1)) {
			perror("+ setenv");
			exit(EXIT_FAILURE);
		}

		if (nochr) {
			lua_pushstring(luas, tmpd);
			lua_setglobal(luas, "prefix");
		}

		if (luaL_dofile(luas, "build.lua") != LUA_OK) {
			fprintf(stderr, "%s\n", lua_tostring(luas, -1));
			lua_pop(luas, 1);
			lua_close(luas);
			exit(EXIT_FAILURE);
		}

		lua_close(luas);
		exit(EXIT_SUCCESS);
	} else {
		int s;
		waitpid(pid, &s, 0);
		if (WIFEXITED(s)) {
			if (WEXITSTATUS(s)) {
				printf("+ Failed to build %s, see "
				       "%s/prometheus.log\n",
				       pname, tmpd);
				return EXIT_FAILURE;
			}
			printf("+ Built %s\n", pname);
		}
	}

	return EXIT_SUCCESS;
}

int
copyfile(const char *s, const char *d)
{
	int sfd, dfd;
	char buf[1024], syms[PATH_MAX], dn[PATH_MAX];
	ssize_t b;

	if (followsymlink(s, syms)) return EXIT_FAILURE;

	if ((sfd = open(syms, O_RDONLY)) == -1) {
		perror("+ open");
		return EXIT_FAILURE;
	}

	strncpy(dn, d, PATH_MAX);
	dirname(dn);
	if (mkdirrecursive(dn)) return EXIT_FAILURE;

	if ((dfd = open(d, O_WRONLY | O_CREAT | O_TRUNC, 0700)) == -1) {
		close(sfd);
		perror("+ open");
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
createtmpdir(char *pname, char dir[PATH_MAX])
{
	char dirtmp[PATH_MAX], log[PATH_MAX], src[PATH_MAX];
	int logfd;

	if (mkdir("/tmp", 0700) == -1 && errno != EEXIST) {
		perror("+ mkdir");
		return EXIT_FAILURE;
	}

	if (PATH_MAX <= strlen("/tmp/prometheus--XXXXXX") + strlen(pname)) {
		printferr("PATH_MAX exceeded");
		return EXIT_FAILURE;
	}
	snprintf(dirtmp, sizeof(dirtmp), "/tmp/prometheus-%s-XXXXXX", pname);
	strncpy(dir, dirtmp, PATH_MAX);
	if (!mkdtemp(dir)) {
		perror("+ mkdtemp");
		return EXIT_FAILURE;
	}

	if (PATH_MAX <= strlen(dir) + strlen("/prometheus.log")) {
		printferr("PATH_MAX exceeded");
		return EXIT_FAILURE;
	}
	snprintf(log, sizeof(log), "%s/prometheus.log", dir);
	if ((logfd = open(log, O_WRONLY | O_CREAT | O_TRUNC, 0700)) == -1) {
		perror("+ open");
		return EXIT_FAILURE;
	}
	close(logfd);

	if (PATH_MAX <= strlen(dir) + strlen("/src")) {
		printferr("PATH_MAX exceeded");
		return EXIT_FAILURE;
	}
	snprintf(src, sizeof(src), "%s/src", dir);
	if (mkdir(src, 0700) == -1 && errno != EEXIST) {
		perror("+ mkdir");
		return EXIT_FAILURE;
	}

	return EXIT_SUCCESS;
}

int
curlprogress(void *p, curl_off_t dltot, curl_off_t dlnow, curl_off_t utot,
             curl_off_t upl)
{
	if (dltot > 0) {
		printf("\r- Downloading %s: %.2f%%",
		       p, (double)dlnow / dltot * 100.0);
		fflush(stdout);
	}

	return 0;
}

size_t
curlwrite(void *d, size_t dl, size_t n, FILE *f)
{
	return fwrite(d, dl, n, f);
}

unsigned int
direxists(const char *f)
{
	struct stat buf;
	if (stat(f, &buf)) return 0;
	if (S_ISDIR(buf.st_mode)) return 1;
	return 0;
}

int
expandtilde(const char *f, char ef[PATH_MAX])
{
	char *home;

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
fetchfile(const char *url, const char *f)
{
	CURL *c;
	CURLcode cc;
	FILE *ff;
	long r;
	char ua[sizeof(PROJECT_NAME) + sizeof(VERSION)]; /* -2^\0 +/ +\0 */

	snprintf(ua, sizeof(ua), "%s/%s", PROJECT_NAME, VERSION);

	if (!(c = curl_easy_init())) {
		fprintf(stderr, "+ curl: Failed to initialize\n");
		return EXIT_FAILURE;
	}

	if (!(ff = fopen(f, "wb"))) {
		curl_easy_cleanup(c);
		perror("+ fopen");
		return EXIT_FAILURE;
	}

	curl_easy_setopt(c, CURLOPT_URL, url);
	curl_easy_setopt(c, CURLOPT_WRITEFUNCTION, curlwrite);
	curl_easy_setopt(c, CURLOPT_WRITEDATA, ff);
	curl_easy_setopt(c, CURLOPT_NOPROGRESS, 0L);
	curl_easy_setopt(c, CURLOPT_XFERINFODATA, url);
	curl_easy_setopt(c, CURLOPT_XFERINFOFUNCTION, curlprogress);
	curl_easy_setopt(c, CURLOPT_FOLLOWLOCATION, 1L);
	curl_easy_setopt(c, CURLOPT_USERAGENT, ua);
	curl_easy_setopt(c, CURLOPT_TIMEOUT, 0L);
	curl_easy_setopt(c, CURLOPT_CONNECTTIMEOUT, 30L);
	curl_easy_setopt(c, CURLOPT_HTTP_VERSION, CURL_HTTP_VERSION_2_0);
	curl_easy_setopt(c, CURLOPT_USE_SSL, CURLUSESSL_ALL);
	curl_easy_setopt(c, CURLOPT_SSL_VERIFYPEER, 1L);
	curl_easy_setopt(c, CURLOPT_SSL_VERIFYHOST, 2L);
	curl_easy_setopt(c, CURLOPT_FTP_USE_EPSV, 1L);
	curl_easy_setopt(c, CURLOPT_FTP_RESPONSE_TIMEOUT, 30L);

	if ((cc = curl_easy_perform(c)) != CURLE_OK) {
		fclose(ff);
		curl_easy_cleanup(c);
		fprintf(stderr, "+ curl %s: %s\n",
		        url, curl_easy_strerror(cc));
		return EXIT_FAILURE;
	}

	printf("\n"); /* needed after curlprogress has been used */
	curl_easy_getinfo(c, CURLINFO_RESPONSE_CODE, &r);

	if (r >= 400) {
		printf("+ curl %s: Response code %ld\n", url, r);
		fclose(ff);
		curl_easy_cleanup(c);
		return EXIT_FAILURE;
	}

	fclose(ff);
	curl_easy_cleanup(c);

	return EXIT_SUCCESS;
}

unsigned int
fileexists(const char *f)
{
	struct stat buf;
	return (!stat(f, &buf));
}

int
followsymlink(const char *f, char ff[PATH_MAX])
{
	struct stat sb;

	strncpy(ff, f, PATH_MAX);

	while (S_ISLNK(sb.st_mode)) {
		ssize_t n;

		if (lstat(f, &sb)) {
			perror("+ lstat");
			return EXIT_FAILURE;
		}

		if ((n = readlink(f, ff, PATH_MAX - 1)) == -1) {
			if (errno == EINVAL || errno == ENOENT) break;
			perror("+ readlink");
			return EXIT_FAILURE;
		}
		ff[n] = '\0';
	}

	return EXIT_SUCCESS;
}

int
getpackages(struct Packages *pkgs)
{
	size_t i;
	DIR *d;
	struct dirent *e;

	if(!(d = opendir(PACKAGE_REPOSITORY))) {
		pkgs->l = 0;
		return EXIT_SUCCESS;
	};

	i = 0;
	while ((e = readdir(d))) {
		char path[PATH_MAX];
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
installpackage(char *pname, char *prefix, unsigned int y)
{
	struct Depends deps;
	struct Outs outs;
	char tmpd[PATH_MAX], nochrf[PATH_MAX];
	int i, pii;
	unsigned int nochr;

	if ((pii = packageisinstalled(pname, prefix)) == -1)
		return EXIT_FAILURE;

	if (pii) {
		printf("+ Skipping %s since it is already installed\n", pname);
		return EXIT_SUCCESS;
	}

	if (PATH_MAX <= strlen(PACKAGE_REPOSITORY) + strlen(pname)
	              + strlen("//nochroot")) {
		printferr("PATH_MAX exceeded");
		return EXIT_FAILURE;
	}
	snprintf(nochrf, sizeof(nochrf), "%s/%s/nochroot",
	         PACKAGE_REPOSITORY, pname);
	if (fileexists(nochrf)) {
		char yp;
		struct Lines l;

		if (readlines(nochrf, &l)) return EXIT_FAILURE;

		printf("\n+ Package %s is a nochroot package: this means it "
		       "will have full access over your machine while "
		       "building.\n\n",
		       pname);

		if (!l.l) {
			printf("  The package provided no motivation for "
			       "it.\n\n");
		} else {
			int i;
			printf("  The following is the motivation provided "
			       "by the package:\n\n");
			for (i = 0; i < l.l; i++) printf("\t%s\n", l.a[i]);
			printf("\n");
		}

		printf("> Continue? (y) ");

		if (!y) {
			yp = getchar();

			if (yp && yp != '\n' && yp != 'y' && yp != 'Y') {
				printf("- Quitting\n");
				return EXIT_FAILURE;
			}
		} else {
			printf("y\n");
		}

		nochr = 1;
		printf("\n");
	}

	if (packageouts(pname, &outs)) return EXIT_FAILURE;
	if (!outs.l) {
		printferr("Package %s has no outs", pname);
		return EXIT_FAILURE;
	}

	if (createtmpdir(pname, tmpd)) return EXIT_FAILURE;

	if (packagedepends(pname, &deps)) return EXIT_FAILURE;
	for (i = 0; i < deps.l; i++) {
		int pe;
		if ((pe = packageexists(deps.a[i].pname)) == -1)
			return EXIT_FAILURE;
		printf("+ Found dependency %s for %s\n",
		       deps.a[i].pname, pname);
		if (!pe) {
			printf("+ Dependency %s does not exist\n",
			       deps.a[i].pname);
			continue;
		}
		if (installpackage(deps.a[i].pname,
		                   deps.a[i].runtime ? prefix : tmpd,
		                   y))
			return EXIT_FAILURE;
	}

	if (buildpackage(pname, tmpd, nochr)) return EXIT_FAILURE;

	for (i = 0; i < outs.l; i++) {
		char s[PATH_MAX];

		if (PATH_MAX <= strlen(tmpd) + strlen(outs.a[i])) {
			printferr("PATH_MAX exceeded");
			return EXIT_FAILURE;
		}
		snprintf(s, sizeof(s), "%s%s", tmpd, outs.a[i]);

		if (!fileexists(s)) {
			printferr("Out file %s has not been installed to %s",
			          outs.a[i], tmpd);
			return EXIT_FAILURE;
		}
	}
	for (i = 0; i < outs.l; i++) {
		char s[PATH_MAX], d[PATH_MAX];

		if (PATH_MAX <= strlen(tmpd) + strlen(outs.a[i])) {
			printferr("PATH_MAX exceeded");
			return EXIT_FAILURE;
		}
		snprintf(s, sizeof(s), "%s%s", tmpd, outs.a[i]);

		if (PATH_MAX <= strlen(prefix) + strlen(outs.a[i])) {
			printferr("PATH_MAX exceeded");
			return EXIT_FAILURE;
		}
		snprintf(d, sizeof(d), "%s%s", prefix, outs.a[i]);

		if (copyfile(s, d)) return EXIT_FAILURE;
	}

	printf("+ Installed %s\n", pname);

	return EXIT_SUCCESS;
}

int
mkdirrecursive(const char *d)
{
	char buf[PATH_MAX], *p = NULL;

	if (PATH_MAX <= strlen(d))
		printferr("PATH_MAX exceeded");
	strncpy(buf, d, sizeof(buf));
	buf[sizeof(buf) - 1] = '\0';

	for (p = buf + 1; *p; p++) {
		if (*p == '/') {
			*p = '\0';
			if (mkdir(buf, 0700) && errno != EEXIST) {
				char e[PATH_MAX];
				if (PATH_MAX <= strlen("+ mkdir ")
				              + strlen(buf)) {
					printferr("PATH_MAX exceeded");
					return EXIT_FAILURE;
				}
				snprintf(e, sizeof(e), "+ mkdir %s", buf);
				perror(e);
				return EXIT_FAILURE;
			}
			*p = '/';
		}
	}
	if (mkdir(d, 0700) && errno != EEXIST) {
		perror("+ mkdir");
		return EXIT_FAILURE;
	}

	return EXIT_SUCCESS;
}

int
packagedepends(char *pname, struct Depends *deps)
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
		char *tok;
		int nfields = 0;

		tok = strtok(l.a[i], " \t");
		while (tok && nfields < 2) {
			char depname[PROGRAM_MAX];

			switch (nfields) {
			case 0:
				if (PROGRAM_MAX <= strlen(tok)) {
					printferr("PROGRAM_MAX exceeded");
					return EXIT_FAILURE;
				}
				strncpy(deps->a[i].pname, tok, PROGRAM_MAX);
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
			nfields++;
			tok = strtok(NULL, " \t");
		}

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
packageexists(char *pname)
{
	char bf[PATH_MAX], of[PATH_MAX];

	if (PATH_MAX <= strlen(PACKAGE_REPOSITORY) + strlen(pname)
	              + strlen("//build.lua")) { /* the longest one */
		printferr("PATH_MAX exceeded");
		return -1;
	}
	snprintf(bf, sizeof(bf), "%s/%s/build.lua", PACKAGE_REPOSITORY, pname);
	snprintf(of, sizeof(of), "%s/%s/outs", PACKAGE_REPOSITORY, pname);

	if (fileexists(bf) && fileexists(of)) return 1;

	return 0;
}

int
packageisinstalled(char *pname, char *prefix)
{
	struct Outs outs;
	int i;

	if (packageouts(pname, &outs)) return -1;

	for (i = 0; i < outs.l; i++) {
		char f[PATH_MAX];
		if (PATH_MAX <= strlen(prefix) + strlen(outs.a[i])) {
			printferr("PATH_MAX exceeded");
			return -1;
		}
		snprintf(f, sizeof(f), "%s%s", prefix, outs.a[i]);
		if (!fileexists(f)) {
			return 0;
		}
	}

	return 1;
}

int
packageouts(char *pname, struct Outs *outs)
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
packagesources(char *pname, struct Sources *srcs)
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
		int nfields = 0;

		tok = strtok(l.a[i], " \t");
		while (tok && nfields < 3) {
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
			nfields++;
			tok = strtok(NULL, " \t");
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
printferr(const char *m, ...)
{
	char pm[DIE_MAX];
	va_list va;

	if (DIE_MAX <= strlen(argv0) + strlen(": ") + strlen(m)) {
		fprintf(stderr, "+ printferr: DIE_MAX exceeded\n");
		return;
	}
	snprintf(pm, sizeof(pm), "+ %s: %s", argv0, m);

	va_start(va, m);

	vfprintf(stderr, pm, va);
	putc('\n', stderr);

	va_end(va);
}

void
printinstalled(char *prefix, struct Packages pkgs)
{
	int i;

	for (i = 0; i < pkgs.l; i++) {
		int pii;
		if ((pii = packageisinstalled(pkgs.a[i], prefix)) == -1)
			EXIT_FAILURE;
		if (pii)
			printf("%s\n", pkgs.a[i]);
	}
}

void
printpackages(struct Packages pkgs)
{
	int i;
	for (i = 0; i < pkgs.l; i++) printf("%s\n", pkgs.a[i]);
}

int
readlines(const char *f, struct Lines *l)
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

void
registerluautils(lua_State *luas)
{
	lua_register(luas, "cd", lua_cd);
	lua_register(luas, "chmod", lua_chmod);
	lua_register(luas, "cp", lua_cp);
	lua_register(luas, "echo", lua_echo);
	lua_register(luas, "exec", lua_exec);
	lua_register(luas, "getenv", lua_getenv);
	lua_register(luas, "mkdir", lua_mkdir);
	lua_register(luas, "setenv", lua_setenv);
	lua_register(luas, "uname", lua_uname);
}

unsigned int
relpathisvalid(char *relpath)
{
	return (!strstr(relpath, "..") && !strstr(relpath, ":")
	     && relpath[0] != '/' && relpath[0] != '.' && relpath[0] != '\0'
	     && relpath[strlen(relpath) - 1] != '/');
}

int
retrievesources(struct Sources srcs, const char *pdir, const char *tmpd)
{
	int i;

	for (i = 0; i < srcs.l; i++) {
		char *b = basename(srcs.a[i].url);

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

				printf("+ Hash of %s does not match:\n",
				       srcs.a[i].url);
				printf("  Expected: %s\n", eh);
				printf("  Got:      %s\n", gh);

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

				printf("+ Hash of %s does not match:\n",
				       srcs.a[i].url);
				printf("  Expected: %s\n", eh);
				printf("  Got:      %s\n", gh);

				return EXIT_FAILURE;
			}
			if (copyfile(sf, df)) return EXIT_FAILURE;
		}

		if (strlen(srcs.a[i].relpath)) {
			char sf[PATH_MAX], df[PATH_MAX], mvd[PATH_MAX],
			     dn[PATH_MAX];

			strncpy(dn, srcs.a[i].relpath, PATH_MAX);
			dirname(dn);

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

			if (PATH_MAX <= strlen(tmpd) + strlen("/src/")
			              + strlen(dn)) {
				printferr("PATH_MAX exceeded");
				return EXIT_FAILURE;
			}
			snprintf(mvd, sizeof(mvd), "%s/src/%s", tmpd, dn);

			if (mkdirrecursive(mvd)) return EXIT_FAILURE;

			if (rename(sf, df)) {
				perror("+ rename");
				return EXIT_FAILURE;
			}
		}
	}

	return EXIT_SUCCESS;
}

void
sha256chartouint8(char c[2 * SHA256_DIGEST_LENGTH + 1],
                  uint8_t u[SHA256_DIGEST_LENGTH])
{
	int i;
	for (i = 0; i < SHA256_DIGEST_LENGTH; i++)
		sscanf(c + i * 2, "%2hhx", &u[i]);
}

int
sha256hash(const char *f, uint8_t h[SHA256_DIGEST_LENGTH])
{
	unsigned char buf[4096];
	size_t br;
	struct sha256 ctx;
	FILE *ff;

	sha256_init(&ctx);

	if (!(ff = fopen(f, "rb"))) {
		perror("+ fopen");
		return EXIT_FAILURE;
	}

	while ((br = fread(buf, 1, sizeof(buf), ff)) > 0)
		sha256_update(&ctx, buf, br);

	if (ferror(ff)) {
		fclose(ff);
		perror("+ ferror");
		return EXIT_FAILURE;
	}

	fclose(ff);
	sha256_sum(&ctx, h);

	return EXIT_SUCCESS;
}

void
sha256uint8tochar(uint8_t u[SHA256_DIGEST_LENGTH],
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
	printf("\n- Quitting\n");
	exit(EXIT_FAILURE);
}

int
uninstallpackage(char *pname, char *prefix, unsigned int rec,
                 struct Packages pkgs)
{
	struct Outs outs;
	int i, pii;

	if ((pii = packageisinstalled(pname, prefix)) == -1)
		return EXIT_FAILURE;

	if (!pii) {
		printf("+ Skipping %s since it is not installed\n", pname);
		return EXIT_SUCCESS;
	}

	for (i = 0; i < pkgs.l; i++) {
		struct Depends pdeps;

		if (packagedepends(pkgs.a[i], &pdeps)) return EXIT_FAILURE;

		for (i = 0; i < pdeps.l; i++) {
			int dpii;
			if ((dpii = packageisinstalled(pkgs.a[i],
			                               prefix)) == -1)
				return EXIT_FAILURE;
			if (!strcmp(pdeps.a[i].pname, pname)
			    && pdeps.a[i].runtime
			    && dpii) {
				printf("+ Skipping %s since %s depends on "
				       "it\n", pname, pkgs.a[i]);
				return EXIT_SUCCESS;
			}
		}
	}

	if (packageouts(pname, &outs)) return EXIT_FAILURE;

	printf("- Uninstalling %s\n", pname);
	for (i = 0; i < outs.l; i++) {
		char f[PATH_MAX];

		if (PATH_MAX <= strlen(prefix) + strlen(outs.a[i]))
			printferr("PATH_MAX exceeded");
		snprintf(f, sizeof(f), "%s%s", prefix, outs.a[i]);

		if (!fileexists(f)) continue;

		if (remove(f)) {
			perror("+ remove");
			return EXIT_FAILURE;
		}
	}
	printf("+ Uninstalled %s\n", pname);

	if (rec) {
		struct Depends deps;
		
		if (packagedepends(pname, &deps)) return EXIT_FAILURE;

		for (i = 0; i < deps.l; i++) {
			int pe;

			if ((pe = packageexists(deps.a[i].pname)) == -1)
				return EXIT_FAILURE;

			if (!deps.a[i].runtime) continue;

			printf("+ Found dependency %s for %s\n",
			       deps.a[i].pname, pname);

			if (!pe) {
				printf("+ Dependency %s does not exist\n",
				       deps.a[i].pname);
				continue;
			}

			if (uninstallpackage(deps.a[i].pname, prefix, rec,
			                     pkgs)) return EXIT_FAILURE;
		}
	}

	return EXIT_SUCCESS;
}

unsigned int
urlisvalid(char *url)
{
	return (!strncmp(url, "http://", 7)
	     || !strncmp(url, "https://", 8)
	     || !strncmp(url, "ftp://", 6));
}

void
usage(void)
{
	fprintf(stderr, "Usage: %s -i [-p prefix] [-y] package ...\n"
	                "       %s -u [-p prefix] [-r] package ...\n"
	                "       %s -l [-p prefix]\n"
	                "       %s -a\n",
	                argv0, argv0, argv0, argv0);
	exit(EXIT_FAILURE);
}

int
main(int argc, char *argv[])
{
	int install = 0,
	    y = 0,
	    uninstall = 0,
	    recuninstall = 0,
	    printinst = 0,
	    printall = 0,
	    prefixdef = 0;
	char prefix[PATH_MAX] = DEFAULT_PREFIX,
	     rprefix[PATH_MAX];

	if (getuid()) {
		fprintf(stderr, "%s: Superuser privileges are required\n",
		        argv[0]);
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
		char *arg = EARGF(usage());
		if (expandtilde(arg, prefix)) return EXIT_FAILURE;
		realpath(prefix, rprefix);
		prefixdef = 1;
		break;
	case 'r':
		recuninstall = 1;
		break;
	case 'y':
		y = 1;
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

	if (y && !install)
		usage();

	if (recuninstall && !uninstall)
		usage();

	if (printall && prefixdef)
		usage();

	handlesignals(sigexit);

	if (rprefix[strlen(rprefix) - 1] == '/')
		rprefix[strlen(rprefix) - 1] = '\0';

	if (!rprefix) {
		printferr("Prefix %s could not be read", rprefix);
		return EXIT_FAILURE;
	}

	if (strlen(rprefix) && !direxists(rprefix)) {
		printferr("Prefix %s does not exist", rprefix);
		return EXIT_FAILURE;
	}

	if (printinst) {
		struct Packages pkgs;
		if (getpackages(&pkgs)) return EXIT_FAILURE;
		printinstalled(rprefix, pkgs);
	}

	if (printall) {
		struct Packages pkgs;
		if (getpackages(&pkgs)) return EXIT_FAILURE;
		printpackages(pkgs);
	}

	/* will not be evaluated when either printinst or prinstall is 1 */
	for (; *argv; argc--, argv++) {
		int pe;

		if ((pe = packageexists(*argv)) == -1) return EXIT_FAILURE;

		if (!pe) {
			printferr("Package %s does not exist", *argv);
			return EXIT_FAILURE;
		}

		if (uninstall) {
			struct Packages pkgs;
			if (getpackages(&pkgs)) return EXIT_FAILURE;
			return uninstallpackage(*argv, rprefix, recuninstall,
			                        pkgs);
		} else {
			return installpackage(*argv, rprefix, y);
		}
	}

	return EXIT_SUCCESS;
}
