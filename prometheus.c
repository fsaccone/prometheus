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
#define LINES_MAX MAX(MAX(DEPENDS_MAX, OUTS_MAX), \
                      MAX(REQUIRES_MAX, SOURCES_MAX))

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

struct Requires {
	char a[REQUIRES_MAX][PROGRAM_MAX];
	size_t l;
};

struct RequiresPath {
	char a[REQUIRES_MAX][PATH_MAX];
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

static int buildpackage(char *pname, const char *tmpd);
static int copyfile(const char *s, const char *d);
static int copyrequires(struct Requires reqs, const char *tmpd);
static int copysources(struct Sources srcs, const char *pdir,
                       const char *tmpd);
static int createtmpdir(char *pname, char dir[PATH_MAX]);
static int curlprogress(void *p, curl_off_t dltot, curl_off_t dlnow,
                        curl_off_t utot, curl_off_t upl);
static size_t curlwrite(void *d, size_t dl, size_t n, FILE *f);
static void die(const char *m, ...);
static unsigned int direxists(const char *f);
static int expandtilde(const char *f, char ef[PATH_MAX]);
static int fetchfile(const char *url, const char *f);
static unsigned int fileexists(const char *f);
static int findinpath(struct Requires reqs, struct RequiresPath *reqsp);
static int followsymlink(const char *f, char ff[PATH_MAX]);
static int getpackages(struct Packages *pkgs);
static void handlesignals(void(*hdl)(int));
static int installpackage(char *pname, char *prefix);
static int mkdirrecursive(const char *d);
static unsigned int packageexists(char *pname);
static unsigned int packageisinstalled(char *pname, char *prefix);
static int packagedepends(char *pname, struct Depends *deps);
static int packageouts(char *pname, struct Outs *outs);
static int packagerequires(char *pname, struct Requires *reqs);
static int packagesources(char *pname, struct Sources *srcs);
static void printinstalled(char *prefix, struct Packages pkgs);
static void printpackages(struct Packages pkgs);
static int readlines(const char *f, struct Lines *l);
static void registerluautils(lua_State *luas);
static unsigned int relpathisvalid(char *relpath);
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
buildpackage(char *pname, const char *tmpd)
{
	char pdir[PATH_MAX], b[PATH_MAX], db[PATH_MAX];
	struct Requires reqs;
	struct Sources srcs;
	pid_t pid;

	if (PATH_MAX <= strlen(PACKAGE_REPOSITORY) + strlen("/")
	              + strlen(pname)) {
		die("PATH_MAX exceeded");
		return EXIT_FAILURE;
	}
	snprintf(pdir, sizeof(pdir), "%s/%s", PACKAGE_REPOSITORY, pname);

	if (PATH_MAX <= strlen(pdir) + strlen("/build.lua")) {
		die("PATH_MAX exceeded");
		return EXIT_FAILURE;
	}
	snprintf(b, sizeof(b), "%s/build.lua", pdir);

	if (PATH_MAX <= strlen(tmpd) + strlen("/prometheus.build.lua")) {
		die("PATH_MAX exceeded");
		return EXIT_FAILURE;
	}
	snprintf(db, sizeof(db), "%s/prometheus.build.lua", tmpd);

	if (copyfile(b, db)) return EXIT_FAILURE;

	if (packagerequires(pname, &reqs)) return EXIT_FAILURE;
	printf("- copying %s's sources\n", pname);
	if (copyrequires(reqs, tmpd)) return EXIT_FAILURE;

	if (packagesources(pname, &srcs)) return EXIT_FAILURE;
	if (copysources(srcs, pdir, tmpd)) return EXIT_FAILURE;
	printf("+ copied %s's sources\n", pname);

	if ((pid = fork()) < 0) {
		perror("fork");
		return EXIT_FAILURE;
	}

	if (!pid) {
		lua_State *luas;
		int logf;

		if (chroot(tmpd)) {
			perror("chroot");
			exit(EXIT_FAILURE);
		}

		printf("- building %s\n", pname);

		if(!(luas = luaL_newstate())) {
			perror("luaL_newstate");
			exit(EXIT_FAILURE);
		}
		luaL_openlibs(luas);
		registerluautils(luas);

		if (!(logf = open("/prometheus.log", O_WRONLY, 0700))) {
			perror("fopen");
			exit(EXIT_FAILURE);
		}
		if (dup2(logf, STDOUT_FILENO) == -1) {
			perror("dup2");
			close(logf);
			exit(EXIT_FAILURE);
		}
		if (dup2(logf, STDERR_FILENO) == -1) {
			perror("dup2");
			close(logf);
			exit(EXIT_FAILURE);
		}
		close(logf);

		if (setenv("PATH", "/bin", 1)) {
			perror("setenv");
			exit(EXIT_FAILURE);
		}

		if (chdir("/src")) {
			perror("chdir");
			exit(EXIT_FAILURE);
		}

		if (luaL_dofile(luas, "/prometheus.build.lua") != LUA_OK) {
			lua_pop(luas, 1);
			lua_close(luas);
			exit(EXIT_FAILURE);
		}
		exit(EXIT_SUCCESS);
	} else {
		int s;
		waitpid(pid, &s, 0);
		if (WIFEXITED(s)) {
			if (WEXITSTATUS(s)) {
				printf("+ failed to build %s, see "
				       "%s/prometheus.log\n",
				       pname, tmpd);
				return EXIT_FAILURE;
			}
			printf("+ built %s\n", pname);
		}
	}

	return EXIT_SUCCESS;
}

int
copyfile(const char *s, const char *d)
{
	int sfd, dfd;
	char buf[1024], syms[PATH_MAX];
	ssize_t b;

	if (followsymlink(s, syms)) return EXIT_FAILURE;

	if ((sfd = open(syms, O_RDONLY)) == -1) {
		perror("open");
		return EXIT_FAILURE;
	}

	if (strrchr(d, '/') && mkdirrecursive(d)) return EXIT_FAILURE;

	if ((dfd = open(d, O_WRONLY | O_CREAT | O_TRUNC, 0700)) == -1) {
		close(sfd);
		perror("open");
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
copyrequires(struct Requires reqs, const char *tmpd)
{
	struct RequiresPath preqs;
	int i;

	if ((findinpath(reqs, &preqs))) return EXIT_FAILURE;

	for (i = 0; i < reqs.l; i++) {
		char d[PATH_MAX];
		if (PATH_MAX <= strlen(tmpd) + strlen(reqs.a[i])
		              + strlen("/bin/")) {
			die("PATH_MAX exceeded");
			return EXIT_FAILURE;
		}
		snprintf(d, sizeof(d), "%s/bin/%s", tmpd, reqs.a[i]);
		if (copyfile(preqs.a[i], d)) return EXIT_FAILURE;
	}

	return EXIT_SUCCESS;
}

int
copysources(struct Sources srcs, const char *pdir, const char *tmpd)
{
	int i;

	for (i = 0; i < srcs.l; i++) {
		char *b = basename(srcs.a[i].url);

		if (urlisvalid(srcs.a[i].url)) {
			char df[PATH_MAX];
			uint8_t h[SHA256_DIGEST_LENGTH];

			if (PATH_MAX <= strlen(tmpd) + strlen(b)
			              + strlen("/src/")) {
				die("PATH_MAX exceeded");
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

				printf("+ hash of %s does not match:\n",
				       srcs.a[i].url);
				printf("  expected: %s\n", eh);
				printf("  got:      %s\n", gh);

				return EXIT_FAILURE;
			}
		} else if (relpathisvalid(srcs.a[i].url)) {
			char sf[PATH_MAX], df[PATH_MAX];
			uint8_t h[SHA256_DIGEST_LENGTH];

			if (PATH_MAX <= strlen(pdir) + strlen("/")
			              + strlen(srcs.a[i].url)) {
				die("PATH_MAX exceeded");
				return EXIT_FAILURE;
			}
			snprintf(sf, sizeof(sf), "%s/%s", pdir, srcs.a[i].url);

			if (PATH_MAX <= strlen(tmpd) + strlen("/src/")
			              + strlen(b)) {
				die("PATH_MAX exceeded");
				return EXIT_FAILURE;
			}
			snprintf(df, sizeof(df), "%s/src/%s", tmpd, b);

			if (!fileexists(sf)) {
				die("URL %s does not exist", srcs.a[i].url);
				return EXIT_FAILURE;
			}

			if (sha256hash(sf, h)) return EXIT_FAILURE;
			if (memcmp(h, srcs.a[i].sha256, SHA256_DIGEST_LENGTH)) {
				char eh[2 * SHA256_DIGEST_LENGTH + 1],
				     gh[2 * SHA256_DIGEST_LENGTH + 1];

				sha256uint8tochar(h, eh);
				sha256uint8tochar(srcs.a[i].sha256, gh);

				printf("+ hash of %s does not match:\n",
				       srcs.a[i].url);
				printf("  expected: %s\n", eh);
				printf("  got:      %s\n", gh);

				return EXIT_FAILURE;
			}
			if (copyfile(sf, df)) return EXIT_FAILURE;
		}

		if (srcs.a[i].relpath) {
			char sf[PATH_MAX], df[PATH_MAX], mvd[PATH_MAX],
			     *dn = dirname(srcs.a[i].relpath);

			if (PATH_MAX <= strlen(tmpd) + strlen("/src/")
			              + strlen(b)) {
				die("PATH_MAX exceeded");
				return EXIT_FAILURE;
			}
			snprintf(sf, sizeof(sf), "%s/src/%s", tmpd, b);


			if (PATH_MAX <= strlen(tmpd) + strlen("/src/")
			              + strlen(srcs.a[i].relpath)) {
				die("PATH_MAX exceeded");
				return EXIT_FAILURE;
			}
			snprintf(df, sizeof(df), "%s/src/%s",
			         tmpd, srcs.a[i].relpath);

			if (PATH_MAX <= strlen(tmpd) + strlen("/src/")
			              + strlen(dn)) {
				die("PATH_MAX exceeded");
				return EXIT_FAILURE;
			}
			snprintf(mvd, sizeof(mvd), "%s/src/%s", tmpd, dn);

			if (strrchr(dn, '/') && mkdirrecursive(mvd))
				return EXIT_FAILURE;

			if (rename(sf, df)) {
				perror("rename");
				return EXIT_FAILURE;
			}
		}
	}

	return EXIT_SUCCESS;
}

int
createtmpdir(char *pname, char dir[PATH_MAX])
{
	char dirtmp[PATH_MAX], log[PATH_MAX], bin[PATH_MAX], src[PATH_MAX];
	int logfd;

	if (mkdir("/tmp", 0700) == -1 && errno != EEXIST) {
		perror("mkdir");
		return EXIT_FAILURE;
	}

	if (PATH_MAX <= strlen("/tmp/prometheus--XXXXXX") + strlen(pname)) {
		die("PATH_MAX exceeded");
		return EXIT_FAILURE;
	}
	snprintf(dirtmp, sizeof(dirtmp), "/tmp/prometheus-%s-XXXXXX", pname);
	strncpy(dir, dirtmp, PATH_MAX);
	if (!mkdtemp(dir)) {
		perror("mkdtemp");
		return EXIT_FAILURE;
	}

	if (PATH_MAX <= strlen(dir) + strlen("/prometheus.log")) {
		die("PATH_MAX exceeded");
		return EXIT_FAILURE;
	}
	snprintf(log, sizeof(log), "%s/prometheus.log", dir);
	if ((logfd = open(log, O_WRONLY | O_CREAT | O_TRUNC, 0700)) == -1) {
		perror("open");
		return EXIT_FAILURE;
	}
	close(logfd);

	if (PATH_MAX <= strlen(dir) + strlen("/src")) {
		die("PATH_MAX exceeded");
		return EXIT_FAILURE;
	}
	snprintf(src, sizeof(src), "%s/src", dir);
	if (mkdir(src, 0700) == -1 && errno != EEXIST) {
		perror("mkdir");
		return EXIT_FAILURE;
	}

	if (PATH_MAX <= strlen(dir) + strlen("/bin")) {
		die("PATH_MAX exceeded");
		return EXIT_FAILURE;
	}
	snprintf(bin, sizeof(bin), "%s/bin", dir);
	if (mkdir(bin, 0700) == -1 && errno != EEXIST) {
		perror("mkdir");
		return EXIT_FAILURE;
	}

	return EXIT_SUCCESS;
}

int
curlprogress(void *p, curl_off_t dltot, curl_off_t dlnow, curl_off_t utot,
             curl_off_t upl)
{
	if (dltot > 0) {
		printf("\r- downloading %s: %.2f%%",
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

void
die(const char *m, ...)
{
	char pm[DIE_MAX];
	va_list va;

	if (DIE_MAX <= strlen(argv0) + strlen(": ") + strlen(m)) {
		fprintf(stderr, "+ die: DIE_MAX exceeded\n");
		return;
	}
	snprintf(pm, sizeof(pm), "+ %s: %s", argv0, m);

	va_start(va, m);

	vfprintf(stderr, pm, va);
	putc('\n', stderr);

	va_end(va);
}

unsigned int
direxists(const char *f)
{
	struct stat buf;
	if (stat(f, &buf) != 0) return 0;
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
		die("cannot expand tilde since HOME is undefined");
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
		fprintf(stderr, "+ curl: failed to initialize\n");
		return EXIT_FAILURE;
	}

	if (!(ff = fopen(f, "wb"))) {
		curl_easy_cleanup(c);
		perror("fopen");
		return EXIT_FAILURE;
	}

	curl_easy_setopt(c, CURLOPT_URL, url);
	curl_easy_setopt(c, CURLOPT_WRITEFUNCTION, curlwrite);
	curl_easy_setopt(c, CURLOPT_WRITEDATA, ff);
	curl_easy_setopt(c, CURLOPT_FOLLOWLOCATION, 1L);
	curl_easy_setopt(c, CURLOPT_USERAGENT, ua);
	curl_easy_setopt(c, CURLOPT_TIMEOUT, 0L);
	curl_easy_setopt(c, CURLOPT_CONNECTTIMEOUT, 10L);
	curl_easy_setopt(c, CURLOPT_HTTP_VERSION, CURL_HTTP_VERSION_2_0);
	curl_easy_setopt(c, CURLOPT_USE_SSL, CURLUSESSL_ALL);
	curl_easy_setopt(c, CURLOPT_SSL_VERIFYPEER, 1L);
	curl_easy_setopt(c, CURLOPT_SSL_VERIFYHOST, 2L);
	curl_easy_setopt(c, CURLOPT_FTP_USE_EPSV, 1L);
	curl_easy_setopt(c, CURLOPT_FTP_RESPONSE_TIMEOUT, 30L);

	if ((cc = curl_easy_perform(c)) != CURLE_OK) {
		fclose(ff);
		curl_easy_cleanup(c);
		fprintf(stderr, "+ curl: %s\n", curl_easy_strerror(cc));
		return EXIT_FAILURE;
	}

	curl_easy_getinfo(c, CURLINFO_RESPONSE_CODE, &r);

	if (r >= 400) {
		printf("+ failed to fetch URL %s: response code is %ld\n",
		       url, r);
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
findinpath(struct Requires reqs, struct RequiresPath *reqsp)
{
	char *pathenv;
	size_t i;

	if (!(pathenv = getenv("PATH"))) {
		die("PATH is not set");
		return EXIT_FAILURE;
	}

	for (i = 0; i < reqs.l; i++) {
		char *pathd, path[PATH_MAX];
		unsigned int set = 0;

		strncpy(path, pathenv, PATH_MAX);

		for (pathd = strtok(path, ":"); path; pathd = strtok(NULL, ":")) {
			char pp[PATH_MAX];

			if (set) break;

			if (PATH_MAX <= strlen(pathd) + strlen("/")
			              + strlen(reqs.a[i])) {
				die("PATH_MAX exceeded");
				return EXIT_FAILURE;
			}
			snprintf(pp, sizeof(pp), "%s/%s", pathd, reqs.a[i]);

			if (!fileexists(pp)) continue;
			set = 1;

			strncpy(reqsp->a[i], pp, PATH_MAX);
		}

		if (!set) {
			die("program %s does not exist", reqs.a[i]);
			return EXIT_FAILURE;
		}
	}

	reqsp->l = i;

	return EXIT_SUCCESS;
}

int
followsymlink(const char *f, char ff[PATH_MAX])
{
	struct stat sb;

	strncpy(ff, f, PATH_MAX);

	while (S_ISLNK(sb.st_mode)) {
		ssize_t n;

		if (lstat(f, &sb)) {
			perror("lstat");
			return EXIT_FAILURE;
		}

		if ((n = readlink(f, ff, PATH_MAX - 1)) == -1) {
			if (errno == EINVAL || errno == ENOENT) break;
			perror("readlink");
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

		if (e->d_name[0] == '.' || e->d_type != DT_DIR
		 || !strcmp(e->d_name, ".") || !strcmp(e->d_name, "..")
		 || !packageexists(e->d_name))
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
installpackage(char *pname, char *prefix)
{
	struct Depends deps;
	struct Outs outs;
	char env[PATH_MAX];
	int i;

	if (packageisinstalled(pname, prefix)) {
		printf("+ skipping %s since it is already installed\n", pname);
		return EXIT_SUCCESS;
	}

	if (createtmpdir(pname, env)) return EXIT_FAILURE;

	if (packagedepends(pname, &deps)) return EXIT_FAILURE;
	for (i = 0; i < deps.l; i++) {
		printf("+ found dependency %s for %s\n",
		       deps.a[i].pname, pname);
		if (!packageexists(deps.a[i].pname)) {
			printf("+ dependency %s does not exist\n",
			       deps.a[i].pname);
			continue;
		}
		if (installpackage(deps.a[i].pname,
		                            deps.a[i].runtime ? prefix : env))
			return EXIT_FAILURE;
	}

	if (buildpackage(pname, env)) return EXIT_FAILURE;

	if (packageouts(pname, &outs)) return EXIT_FAILURE;
	for (i = 0; i < outs.l; i++) {
		char s[PATH_MAX], d[PATH_MAX];

		if (PATH_MAX <= strlen(env) + strlen(outs.a[i])) {
			die("PATH_MAX exceeded");
			return EXIT_FAILURE;
		}
		snprintf(s, sizeof(s), "%s%s", env, outs.a[i]);

		if (!fileexists(s)) {
			die("file %s in %s's outs in was not installed",
			    s, pname);
			return EXIT_FAILURE;
		}

		if (PATH_MAX <= strlen(prefix) + strlen(outs.a[i])) {
			die("PATH_MAX exceeded");
			return EXIT_FAILURE;
		}
		snprintf(d, sizeof(d), "%s%s", prefix, outs.a[i]);

		if (copyfile(s, d)) return EXIT_FAILURE;
	}

	return EXIT_SUCCESS;
}

int
mkdirrecursive(const char *d)
{
	char buf[PATH_MAX], *p = NULL;

	if (PATH_MAX <= strlen(d))
		die("PATH_MAX exceeded");
	strncpy(buf, d, sizeof(buf));
	buf[sizeof(buf) - 1] = '\0';

	for (p = buf + 1; *p; p++) {
		if (*p == '/') {
			*p = '\0';
			if (mkdir(buf, 0700) && errno != EEXIST) {
				perror("mkdir");
				return EXIT_FAILURE;
			}
			*p = '/';
		}
	}

	return EXIT_SUCCESS;
}

unsigned int
packageexists(char *pname)
{
	char bf[PATH_MAX], of[PATH_MAX], sf[PATH_MAX];

	if (PATH_MAX <= strlen(PACKAGE_REPOSITORY) + strlen(pname)
	              + strlen("/build.lua")) { /* the longest one */
		die("PATH_MAX exceeded");
		return 0;
	}
	snprintf(bf, sizeof(bf), "%s/%s/build.lua", PACKAGE_REPOSITORY, pname);
	snprintf(of, sizeof(of), "%s/%s/outs", PACKAGE_REPOSITORY, pname);
	snprintf(sf, sizeof(sf), "%s/%s/sources", PACKAGE_REPOSITORY, pname);

	if (fileexists(bf) && fileexists(of) && fileexists(sf)) return 1;

	return 0;
}

unsigned int
packageisinstalled(char *pname, char *prefix)
{
	struct Outs outs;
	int i;

	if (packageouts(pname, &outs)) return 0;

	for (i = 0; i < outs.l; i++) {
		char f[PATH_MAX];
		if (PATH_MAX <= strlen(prefix) + strlen(outs.a[i])) {
			die("PATH_MAX exceeded");
			return 0;
		}
		snprintf(f, sizeof(f), "%s%s", prefix, outs.a[i]);
		if (!fileexists(f)) {
			return 0;
		}
	}

	return 1;
}

int
packagedepends(char *pname, struct Depends *deps)
{
	size_t i;
	char f[PATH_MAX];
	struct Lines l;

	if (PATH_MAX <= strlen(PACKAGE_REPOSITORY) + strlen(pname)
	              + strlen("//depends")) {
		die("PATH_MAX exceeded");
		return EXIT_FAILURE;
	}
	snprintf(f, sizeof(f), "%s/%s/depends", PACKAGE_REPOSITORY, pname);
	if (readlines(f, &l)) return EXIT_FAILURE;

	for (i = 0; i < l.l; i++) {
		char dname[65],
		     sndfield[8];
		int nfields;

		dname[0] = '\0';
		sndfield[0] = '\0';

		if ((nfields = sscanf(l.a[i], "%64s %7s", dname,
		                      sndfield)) < 1) {
			die("PACKAGE not present in one of %s's depends",
			    pname);
			return EXIT_FAILURE;
		}

		dname[strcspn(dname, "\n")] = '\0';
		if (PROGRAM_MAX <= strlen(dname)) {
			die("PROGRAM_MAX exceeded");
			return EXIT_FAILURE;
		}
		strncpy(deps->a[i].pname, dname, PROGRAM_MAX);
		deps->a[i].pname[65] = '\0';
		if (nfields < 2) {
			deps->a[i].runtime = 0;
		} else if (!strcmp(sndfield, "runtime")) {
			deps->a[i].runtime = 1;
		} else {
			die("the second field in one of %s's depends is "
			    "something different than runtime", pname);
			return EXIT_FAILURE;
		}
	}
	deps->l = i;

	return EXIT_SUCCESS;
}

int
packageouts(char *pname, struct Outs *outs)
{
	size_t i;
	struct Lines l;
	char f[PATH_MAX];

	if (PATH_MAX <= strlen(PACKAGE_REPOSITORY) + strlen(pname)
	              + strlen("//outs")) {
		die("PATH_MAX exceeded");
		return EXIT_FAILURE;
	}
	snprintf(f, sizeof(f), "%s/%s/outs", PACKAGE_REPOSITORY, pname);
	if (readlines(f, &l)) return EXIT_FAILURE;

	for (i = 0; i < l.l; i++) {
		if (l.a[i][0] == '\0') {
			die("empty path found in %s's outs", pname);
			return EXIT_FAILURE;
		}

		if (l.a[i][0] != '/') {
			die("non-absolute path found in %s's outs",
			    pname);
			return EXIT_FAILURE;
		}

		strncpy(outs->a[i], l.a[i], PATH_MAX);
	}
	outs->l = i;

	return EXIT_SUCCESS;
}

int
packagerequires(char *pname, struct Requires *reqs)
{
	struct Lines l;
	char f[PATH_MAX];
	size_t i;

	if (PATH_MAX <= strlen(PACKAGE_REPOSITORY) + strlen(pname)
	              + strlen("//requires")) {
		die("PATH_MAX exceeded");
		return EXIT_FAILURE;
	}
	snprintf(f, sizeof(f), "%s/%s/requires", PACKAGE_REPOSITORY, pname);
	if (readlines(f, &l)) return EXIT_FAILURE;

	for (i = 0; i < l.l; i++) {
		if (l.a[i][0] == '\0') {
			die("empty line found in %s's requires", pname);
			return EXIT_FAILURE;
		}
		strncpy(reqs->a[i], l.a[i], PROGRAM_MAX);
	}
	reqs->l = i;

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
		die("PATH_MAX exceeded");
		return EXIT_FAILURE;
	}
	snprintf(f, sizeof(f), "%s/%s/sources", PACKAGE_REPOSITORY, pname);
	if (readlines(f, &l)) return EXIT_FAILURE;

	for (i = 0; i < l.l; i++) {
		char sha256[2 * SHA256_DIGEST_LENGTH + 1],
		     url[PATH_MAX],
		     relpath[PATH_MAX],
		     *tok;
		uint8_t sha256bin[SHA256_DIGEST_LENGTH];
		int nfields;

		sha256[0] = '\0';
		url[0] = '\0';
		relpath[0] = '\0';

		tok = strtok(l.a[i], " \t\n");
		while (tok && nfields < 3) {
			switch (nfields) {
			case 0:
				if (2 * SHA256_DIGEST_LENGTH != strlen(tok)) {
					die("SHA256 is not valid");
					return EXIT_FAILURE;
				}
				strncpy(sha256, tok, 2 * SHA256_DIGEST_LENGTH);
				sha256[2 * SHA256_DIGEST_LENGTH] = '\0';
				break;
			case 1:
				if (PATH_MAX <= strlen(tok)) {
					die("PATH_MAX exceeded");
					return EXIT_FAILURE;
				}
				strncpy(url, tok, PATH_MAX);
				url[PATH_MAX - 1] = '\0';
				break;
			case 2:
				if (PATH_MAX <= strlen(tok)) {
					die("PATH_MAX exceeded");
					return EXIT_FAILURE;
				}
				strncpy(relpath, tok, PATH_MAX);
				sha256[PATH_MAX - 1] = '\0';
				break;
			default:
			}
			nfields++;
			tok = strtok(NULL, " \t\n");
		}

		if (nfields < 1) {
			die("SHA256 not present in one of %s's sources",
			    pname);
			return EXIT_FAILURE;
		}
		else if (nfields < 2) {
			die("URL not present in one of %s's sources", pname);
			return EXIT_FAILURE;
		}

		sha256chartouint8(sha256, sha256bin);
		memcpy(srcs->a[i].sha256, sha256bin, SHA256_DIGEST_LENGTH);

		url[strcspn(url, "\n")] = '\0';
		if (!relpathisvalid(url) && !urlisvalid(url)) {
			die("URL %s is not valid", url);
			return EXIT_FAILURE;
		}
		if (PATH_MAX <= strlen(url)) {
			die("PATH_MAX exceeded");
			return EXIT_FAILURE;
		}
		strncpy(srcs->a[i].url, url, PATH_MAX);
		srcs->a[i].url[255] = '\0';

		if (nfields == 3) {
			relpath[strcspn(relpath, "\n")] = '\0';
			if (!relpathisvalid(relpath)) {
				die("RELPATH %s is not valid", relpath);
				return EXIT_FAILURE;
			}
			if (PATH_MAX <= strlen(relpath)) {
				die("PATH_MAX exceeded");
				return EXIT_FAILURE;
			}
			strncpy(srcs->a[i].relpath, relpath, PATH_MAX);
			srcs->a[i].relpath[255] = '\0';
		}
	}
	srcs->l = i;

	return EXIT_SUCCESS;
}

void
printinstalled(char *prefix, struct Packages pkgs)
{
	int i;

	for (i = 0; i < pkgs.l; i++) {
		if (packageisinstalled(pkgs.a[i], prefix))
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
		buf[strcspn(buf, "\n")] = '\0';
		strncpy(l->a[i], buf, LINE_MAX);
		i++;
		if (i >= LINES_MAX) {
			die("LINES_MAX exceeded");
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
	lua_register(luas, "cp", lua_cp);
	lua_register(luas, "exec", lua_exec);
	lua_register(luas, "mkdir", lua_mkdir);
}

unsigned int
relpathisvalid(char *relpath)
{
	return (!strstr(relpath, "..") && !strstr(relpath, ":")
	                               && relpath[0] != '/'
	                               && relpath[0] != '.');
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
		perror("fopen");
		return EXIT_FAILURE;
	}

	while ((br = fread(buf, 1, sizeof(buf), ff)) > 0)
		sha256_update(&ctx, buf, br);

	if (ferror(ff)) {
		fclose(ff);
		perror("ferror");
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
	printf("\n- quitting\n");
	exit(EXIT_FAILURE);
}

int
uninstallpackage(char *pname, char *prefix, unsigned int rec,
                 struct Packages pkgs)
{
	struct Outs outs;
	int i;

	if (!packageisinstalled(pname, prefix)) {
		printf("+ skipping %s since it is not installed\n", pname);
		return EXIT_SUCCESS;
	}

	for (i = 0; i < pkgs.l; i++) {
		struct Depends pdeps;

		if (packagedepends(pkgs.a[i], &pdeps)) return EXIT_FAILURE;

		for (i = 0; i < pdeps.l; i++) {
			if (!strcmp(pdeps.a[i].pname, pname)
			    && pdeps.a[i].runtime
			    && packageisinstalled(pkgs.a[i], prefix)) {
				printf("+ skipping %s since %s depends on "
				       "it\n", pname, pkgs.a[i]);
				return EXIT_SUCCESS;
			}
		}
	}

	printf("- uninstalling %s\n", pname);
	for (i = 0; i < outs.l; i++) {
		char *f;

		if (PATH_MAX <= strlen(prefix) + strlen(outs.a[i]))
			die("PATH_MAX exceeded");
		snprintf(f, sizeof(f), "%s%s", prefix, outs.a[i]);

		if (!fileexists(f)) continue;

		if (remove(f)) {
			perror("remove");
			return EXIT_FAILURE;
		}
	}
	printf("+ uninstalled %s\n", pname);

	if (rec) {
		struct Depends deps;
		
		if (packagedepends(pname, &deps)) return EXIT_FAILURE;

		for (i = 0; i < deps.l; i++) {
			if (!deps.a[i].runtime) continue;

			printf("+ found dependency %s for %s\n",
			       deps.a[i].pname, pname);

			if (!packageexists(deps.a[i].pname)) {
				printf("+ dependency %s does not exist\n",
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
	fprintf(stderr, "usage: %s -i [-p prefix] package ...\n"
	                "       %s -u [-p prefix] [-r]  package ...\n"
	                "       %s -l [-p prefix]\n"
	                "       %s -a\n",
	                argv0, argv0, argv0, argv0);
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
	char prefix[PATH_MAX] = DEFAULT_PREFIX,
	     rprefix[PATH_MAX];

	if (getuid()) {
		fprintf(stderr, "%s: superuser privileges are required\n",
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

	handlesignals(sigexit);

	if (rprefix[strlen(rprefix) - 1] == '/')
		rprefix[strlen(rprefix) - 1] = '\0';

	if (!rprefix) {
		die("prefix %s could not be read", rprefix);
		return EXIT_FAILURE;
	}

	if (strlen(rprefix) && !direxists(rprefix)) {
		die("prefix %s does not exist", rprefix);
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
		if (!packageexists(*argv)) {
			die("package %s does not exist", *argv);
			return EXIT_FAILURE;
		}

		if (uninstall) {
			struct Packages pkgs;
			if (getpackages(&pkgs)) return EXIT_FAILURE;
			return uninstallpackage(*argv, rprefix, recuninstall,
			                        pkgs);
		} else {
			return installpackage(*argv, rprefix);
		}
	}

	return EXIT_SUCCESS;
}
