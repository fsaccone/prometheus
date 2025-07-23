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
#include "sha256.h"

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
	char *url;
	char *relpath;
};

struct SourceNode {
	struct Source v;
	struct SourceNode *n;
};

static void buildpackage(char *pname, const char *tmpd);
static void copyfile(const char *s, const char *d);
static void copyrequires(struct Requires reqs, const char *tmpd);
static void copysources(struct SourceNode *srcs, const char *pdir,
                        const char *tmpd);
static char *createtmpdir(char *pname);
static size_t curlwrite(void *d, size_t dl, size_t n, FILE *f);
static void die(const char *m, ...);
static unsigned int direxists(const char *f);
static char *expandtilde(const char *f);
static void fetchfile(const char *url, const char *f);
static unsigned int fileexists(const char *f);
static struct RequiresPath findinpath(struct Requires reqs);
static char *followsymlink(const char *f);
static void freesourcellist(struct SourceNode *n);
static struct Packages getpackages(void);
static void handlesignals(void(*hdl)(int));
static void installpackage(char *pname, char *prefix);
static void mkdirrecursive(const char *d);
static unsigned int packageexists(char *pname);
static unsigned int packageisinstalled(char *pname, char *prefix);
static struct Depends packagedepends(char *pname);
static struct Outs packageouts(char *pname);
static struct Requires packagerequires(char *pname);
static struct SourceNode *packagesources(char *pname);
static void printinstalled(char *prefix, struct Packages pkgs);
static struct Lines readlines(const char *f);
static unsigned int relpathisvalid(char *relpath);
static uint8_t *sha256chartouint8(const char *c);
static uint8_t *sha256hash(const char *f);
static char *sha256uint8tochar(const uint8_t *u);
static void sigcleanup();
static void uninstallpackage(char *pname, char *prefix, unsigned int rec,
                             struct Packages pkgs);
static unsigned int urlisvalid(char *url);
static void usage(void);

void
buildpackage(char *pname, const char *tmpd)
{
	char *pdir, *b, *db;
	size_t pdirl, bl, dbl;
	struct Requires reqs;
	struct SourceNode *srcs;
	pid_t pid;

	printf("- building %s\n", pname);

	pdirl = strlen(pkgsrepodir) + strlen(pname) + 2; /* / + \0 */
	if (!(pdir = malloc(pdirl))) {
		perror("malloc");
		exit(EXIT_FAILURE);
	}
	snprintf(pdir, pdirl, "%s/%s", pkgsrepodir, pname);

	bl = pdirl - 1 + 12; /* / + /build.lua + \0 */
	if (!(b = malloc(bl))) {
		free(pdir);
		perror("malloc");
		exit(EXIT_FAILURE);
	}
	snprintf(b, bl, "%s/build.lua", pdir);

	dbl = strlen(tmpd) + 22; /* /prometheus.build.lua + \0 */
	if (!(db = malloc(dbl))) {
		free(pdir);
		free(b);
		perror("malloc");
		exit(EXIT_FAILURE);
	}
	snprintf(db, dbl, "%s/prometheus.build.lua", tmpd);

	copyfile(b, db);
	free(b);
	free(db);

	reqs = packagerequires(pname);
	copyrequires(reqs, tmpd);

	srcs = packagesources(pname);
	copysources(srcs, pdir, tmpd);
	freesourcellist(srcs);
	free(pdir);

	if ((pid = fork()) < 0) {
		perror("fork");
		exit(EXIT_FAILURE);
	}

	if (!pid) {
		lua_State *luas;
		int logf;

		if (chroot(tmpd)) {
			perror("chroot");
			exit(EXIT_FAILURE);
		}

		if(!(luas = luaL_newstate())) {
			perror("luaL_newstate");
			exit(EXIT_FAILURE);
		}
		luaL_openlibs(luas);

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
				exit(EXIT_FAILURE);
			}
			printf("+ built %s\n", pname);
		}
	}
}

void
copyfile(const char *s, const char *d)
{
	int sfd, dfd;
	char buf[1024], *syms;
	ssize_t b;

	syms = followsymlink(s);

	if ((sfd = open(syms, O_RDONLY)) == -1) {
		free(syms);
		perror("open");
		exit(EXIT_FAILURE);
	}
	free(syms);

	if (strrchr(d, '/')) mkdirrecursive(d);

	if ((dfd = open(d, O_WRONLY | O_CREAT | O_TRUNC, 0700)) == -1) {
		close(sfd);
		perror("open");
		exit(EXIT_FAILURE);
	}

	while ((b = read(sfd, buf, sizeof(buf))) > 0) {
		write(dfd, buf, b);
	}

	close(sfd);
	close(dfd);
}

void
copyrequires(struct Requires reqs, const char *tmpd)
{
	char *bin;
	size_t binl;
	struct RequiresPath preqs;
	int i;

	preqs = findinpath(reqs);

	binl = strlen(tmpd) + 5; /* /bin + \0 */
	if (!(bin = malloc(binl))) {
		perror("malloc");
		exit(EXIT_FAILURE);
	}
	snprintf(bin, binl, "%s/bin", tmpd);
	if (preqs.l > 0 && mkdir(bin, 0700) && errno != EEXIST) {
		free(bin);
		perror("mkdir");
		exit(EXIT_FAILURE);
	}
	free(bin);

	for (i = 0; i < reqs.l; i++) {
		char *d;
		size_t dl = strlen(tmpd) + strlen(reqs.a[i]) + 6; /* /bin/ + \0 */
		if (!(d = malloc(dl))) {
			perror("malloc");
			exit(EXIT_FAILURE);
		}
		snprintf(d, dl, "%s/bin/%s", tmpd, reqs.a[i]);
		copyfile(preqs.a[i], d);
		free(d);
	}
}

void
copysources(struct SourceNode *srcs, const char *pdir, const char *tmpd)
{
	struct SourceNode *s;

	for (s = srcs; s; s = s->n) {
		char *b = basename(s->v.url);

		if (urlisvalid(s->v.url)) {
			char *df;
			size_t dfl;
			uint8_t *h;

			dfl = strlen(tmpd) + strlen(b) + 6; /* /src/ + \0 */
			if (!(df = malloc(dfl))) {
				perror("malloc");
				exit(EXIT_FAILURE);
			}
			snprintf(df, dfl, "%s/src/%s", tmpd, b);

			fetchfile(s->v.url, df);

			h = sha256hash(df);
			free(df);
			if (memcmp(h, s->v.sha256, SHA256_DIGEST_LENGTH)) {
				char *eh, *gh;

				eh = sha256uint8tochar(h);
				gh = sha256uint8tochar(s->v.sha256);
				free(h);

				printf("+ hash of %s does not match:\n",
				       s->v.url);
				printf("  expected: %s\n", eh);
				printf("  got:      %s\n", gh);

				exit(EXIT_FAILURE);
			}
		} else if (relpathisvalid(s->v.url)) {
			char *sf, *df;
			size_t sfl, dfl;
			uint8_t *h;

			sfl = strlen(pdir) + strlen(s->v.url) + 2; /* / + \0 */
			if (!(sf = malloc(sfl))) {
				perror("malloc");
				exit(EXIT_FAILURE);
			}
			snprintf(sf, sfl, "%s/%s", pdir, s->v.url);

			dfl = strlen(tmpd) + strlen(b) + 6; /* /src/ + \0 */
			if (!(df = malloc(dfl))) {
				free(sf);
				perror("malloc");
				exit(EXIT_FAILURE);
			}
			snprintf(df, dfl, "%s/src/%s", tmpd, b);

			if (!fileexists(sf))
				die("%s: URL %s does not exist",
				    argv0, s->v.url);

			h = sha256hash(sf);
			if (memcmp(h, s->v.sha256, SHA256_DIGEST_LENGTH)) {
				char *eh, *gh;

				eh = sha256uint8tochar(h);
				gh = sha256uint8tochar(s->v.sha256);
				free(h);

				printf("+ hash of %s does not match:\n",
				       s->v.url);
				printf("  expected: %s\n", eh);
				printf("  got:      %s\n", gh);

				free(sf);
				free(df);
				free(eh);
				free(gh);
				exit(EXIT_FAILURE);
			}
			copyfile(sf, df);
			free(h);
			free(sf);
			free(df);
		}

		if (s->v.relpath) {
			char *sf, *df, *dn = dirname(s->v.relpath), *mvd;
			size_t sfl, dfl, mvdl;

			sfl = strlen(tmpd) + strlen(b) + 6; /* /src/ + \0 */
			if (!(sf = malloc(sfl))) {
				perror("malloc");
				exit(EXIT_FAILURE);
			}
			snprintf(sf, sfl, "%s/src/%s", tmpd, b);

			dfl = strlen(tmpd) + strlen(s->v.relpath)
			    + 6; /* /src/ + \0 */
			if (!(df = malloc(dfl))) {
				free(sf);
				perror("malloc");
				exit(EXIT_FAILURE);
			}
			snprintf(df, dfl, "%s/src/%s", tmpd, s->v.relpath);

			mvdl = strlen(tmpd) + strlen(dn) + 6; /* /src/ + \0 */
			if (!(mvd = malloc(mvdl))) {
				free(sf);
				free(df);
				perror("malloc");
				exit(EXIT_FAILURE);
			}
			snprintf(mvd, mvdl, "%s/src/%s", tmpd, dn);

			if (strrchr(dn, '/')) mkdirrecursive(mvd);
			free(mvd);

			if (rename(sf, df)) {
				free(sf);
				free(df);
				perror("rename");
				exit(EXIT_FAILURE);
			}

			free(sf);
			free(df);
		}
	}
}

char *
createtmpdir(char *pname)
{
	char *dir, *log, *src;
	size_t dirl, logl, srcl;
	int logfd;

	if (mkdir("/tmp", 0700) == -1 && errno != EEXIST) {
		perror("mkdir");
		exit(EXIT_FAILURE);
	}

	dirl = strlen(pname) + 24; /* /tmp/prometheus--XXXXXX + \0 */
	if (!(dir = malloc(dirl))) {
		perror("malloc");
		exit(EXIT_FAILURE);
	}
	snprintf(dir, dirl, "/tmp/prometheus-%s-XXXXXX", pname);
	if (!mkdtemp(dir)) {
		free(dir);
		perror("mkdtemp");
		exit(EXIT_FAILURE);
	}

	logl = strlen(dir) + 16; /* /prometheus.log + \0 */
	if (!(log = malloc(logl))) {
		free(dir);
		perror("malloc");
		exit(EXIT_FAILURE);
	}
	snprintf(log, logl, "%s/prometheus.log", dir);
	if ((logfd = open(log, O_WRONLY | O_CREAT | O_TRUNC, 0700)) == -1) {
		free(dir);
		free(log);
		perror("open");
		exit(EXIT_FAILURE);
	}
	free(log);
	close(logfd);

	srcl = strlen(dir) + 5; /* /src + \0 */
	if (!(src = malloc(srcl))) {
		perror("malloc");
		exit(EXIT_FAILURE);
	}
	snprintf(src, srcl, "%s/src", dir);
	if (mkdir(src, 0700) == -1 && errno != EEXIST) {
		free(src);
		perror("mkdir");
		exit(EXIT_FAILURE);
	}
	free(src);

	return dir;
}

size_t
curlwrite(void *d, size_t dl, size_t n, FILE *f)
{
	return fwrite(d, dl, n, f);
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

void
fetchfile(const char *url, const char *f)
{
	CURL *c;
	CURLcode cc;
	FILE *ff;
	long r;
	char ua[sizeof(PROJECTNAME) + sizeof(VERSION)]; /* -2^\0 +/ +\0 */

	snprintf(ua, sizeof(ua), "%s/%s", PROJECTNAME, VERSION);

	if (!(c = curl_easy_init()))
		die("curl: failed to initialize");

	if (!(ff = fopen(f, "wb"))) {
		curl_easy_cleanup(c);
		perror("fopen");
		exit(EXIT_FAILURE);
	}

	curl_easy_setopt(c, CURLOPT_URL, url);
	curl_easy_setopt(c, CURLOPT_WRITEFUNCTION, curlwrite);
	curl_easy_setopt(c, CURLOPT_WRITEDATA, ff);
	curl_easy_setopt(c, CURLOPT_FOLLOWLOCATION, 1L);
	curl_easy_setopt(c, CURLOPT_USERAGENT, ua);

	if ((cc = curl_easy_perform(c)) != CURLE_OK) {
		fclose(ff);
		curl_easy_cleanup(c);
		die("curl: %s", curl_easy_strerror(cc));
	}

	curl_easy_getinfo(c, CURLINFO_RESPONSE_CODE, &r);

	if (r >= 400) {
		printf("+ failed to fetch URL %s: response code is %ld\n",
		       url, r);
		fclose(ff);
		curl_easy_cleanup(c);
		exit(EXIT_FAILURE);
	}

	fclose(ff);
	curl_easy_cleanup(c);
}

unsigned int
fileexists(const char *f)
{
	struct stat buf;
	return (!stat(f, &buf));
}

struct RequiresPath
findinpath(struct Requires reqs)
{
	struct RequiresPath new;
	char *pathenv;
	size_t i;

	if (!(pathenv = getenv("PATH")))
		die("%s: PATH is not set", argv0);

	for (i = 0; i < reqs.l; i++) {
		char *path, *pathd;
		unsigned int set = 0;

		if (!(path = malloc(strlen(pathenv) + 1))) {
			perror("malloc");
			exit(EXIT_FAILURE);
		}
		strcpy(path, pathenv);

		for (pathd = strtok(path, ":"); path; pathd = strtok(NULL, ":")) {
			char *pp;
			size_t ppl;

			if (set) break;

			ppl = strlen(pathd) + strlen(reqs.a[i]) + 2; /* / + \0 */
			if (!(pp = malloc(ppl))) {
				perror("malloc");
				exit(EXIT_FAILURE);
			}
			snprintf(pp, ppl, "%s/%s", pathd, reqs.a[i]);

			if (!fileexists(pp)) continue;
			set = 1;

			strncpy(new.a[i], pp, PATH_MAX);
		}

		if (!set)
			die("%s: program %s does not exist",
			    argv0, reqs.a[i]);
	}

	new.l = i;

	return new;
}

char *
followsymlink(const char *f)
{
	char *p, *res;
	struct stat sb;

	if (!(p = malloc(PATH_MAX))) {
		perror("malloc");
		exit(EXIT_FAILURE);
	}
	strcpy(p, f);

	while (S_ISLNK(sb.st_mode)) {
		ssize_t n;

		if ((n = readlink(f, p, PATH_MAX - 1)) == -1) {
			if (errno == EINVAL || errno == ENOENT) break;
			perror("readlink");
			exit(EXIT_FAILURE);
		}
		p[n] = '\0';

		if (lstat(p, &sb)) {
			perror("lstat");
			exit(EXIT_FAILURE);
		}
	}

	if (!(res = malloc(strlen(p) + 1))) {
		perror("malloc");
		exit(EXIT_FAILURE);
	}
	strcpy(res, p);
	free(p);
	return res;
}

void
freesourcellist(struct SourceNode *n)
{
	while (n) {
		struct SourceNode *nn = n->n;
		free(n->v.url);
		if (n->v.relpath) free(n->v.relpath);
		free(n);
		n = nn;
	}
}

struct Packages
getpackages(void)
{
	struct Packages pkgs;
	size_t i;
	DIR *d;
	struct dirent *e;

	if(!(d = opendir(pkgsrepodir))) {
		pkgs.l = 0;
		return pkgs;
	};

	i = 0;
	while ((e = readdir(d))) {
		char path[PATH_MAX];

		if (e->d_name[0] == '.' || e->d_type != DT_DIR
		 || !strcmp(e->d_name, ".") || !strcmp(e->d_name, "..")
		 || !packageexists(e->d_name))
			continue;

		strncpy(pkgs.a[i], e->d_name, NAME_MAX);
		i++;
	}
	pkgs.l = i;

	closedir(d);
	return pkgs;
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
installpackage(char *pname, char *prefix)
{
	struct Depends deps;
	struct Outs outs;
	char *env;
	int i;

	if (packageisinstalled(pname, prefix)) {
		printf("+ skipping %s since it is already installed\n", pname);
		return;
	}

	env = createtmpdir(pname);

	deps = packagedepends(pname);
	for (i = 0; i < deps.l; i++) {
		printf("+ found dependency %s for %s\n",
		       deps.a[i].pname, pname);
		if (!packageexists(deps.a[i].pname)) {
			printf("+ dependency %s does not exist\n",
			       deps.a[i].pname);
			continue;
		}
		installpackage(deps.a[i].pname,
		               deps.a[i].runtime ? prefix : env);
	}

	buildpackage(pname, env);

	outs = packageouts(pname);
	for (i = 0; i < outs.l; i++) {
		char *s, *d;
		size_t ss = strlen(env) + strlen(outs.a[i]) + 1,
		       ds = strlen(prefix) + strlen(outs.a[i]) + 1;

		if (!(s = malloc(ss))) {
			free(env);
			perror("malloc");
			exit(EXIT_FAILURE);
		}
		snprintf(s, ss, "%s%s", env, outs.a[i]);

		if (!fileexists(s)) {
			free(env);
			die("%s: file %s in %s's outs in was not installed",
			    argv0, s, pname);
			free(s);
			exit(EXIT_FAILURE);
		}

		if (!(d = malloc(ds))) {
			free(s);
			free(env);
			perror("malloc");
			exit(EXIT_FAILURE);
		}
		snprintf(d, ds, "%s%s", prefix, outs.a[i]);

		copyfile(s, d);
		free(s);
		free(d);
	}
	free(env);
}

void
mkdirrecursive(const char *d)
{
	char buf[PATH_MAX], *p = NULL;

	if (PATH_MAX <= strlen(d))
		die("%s: PATH_MAX exceeded", argv0);
	strncpy(buf, d, sizeof(buf));
	buf[sizeof(buf) - 1] = '\0';

	for (p = buf + 1; *p; p++) {
		if (*p == '/') {
			*p = '\0';
			if (mkdir(buf, 0700) && errno != EEXIST) {
				perror("mkdir");
				exit(EXIT_FAILURE);
			}
			*p = '/';
		}
	}
}

unsigned int
packageexists(char *pname)
{
	char bf[PATH_MAX], of[PATH_MAX], sf[PATH_MAX];

	if (PATH_MAX <= strlen(pkgsrepodir) + strlen(pname)
	              + strlen("/build.lua")) /* the longest one */
		die("%s: PATH_MAX exceeded", argv0);
	snprintf(bf, sizeof(bf), "%s/%s/build.lua", pkgsrepodir, pname);
	snprintf(of, sizeof(of), "%s/%s/outs", pkgsrepodir, pname);
	snprintf(sf, sizeof(sf), "%s/%s/sources", pkgsrepodir, pname);

	if (fileexists(bf) && fileexists(of) && fileexists(sf)) return 1;

	return 0;
}

unsigned int
packageisinstalled(char *pname, char *prefix)
{
	struct Outs outs = packageouts(pname);
	int i;

	for (i = 0; i < outs.l; i++) {
		size_t fl = strlen(prefix) + strlen(outs.a[i]) + 2; /* / + \0 */
		char *f = malloc(fl);
		snprintf(f, fl, "%s/%s", prefix, outs.a[i]);
		if (!fileexists(f)) {
			free(f);
			return 0;
		}
		free(f);
	}

	return 1;
}

struct Depends
packagedepends(char *pname)
{
	struct Depends deps;
	size_t i;
	char f[PATH_MAX];
	struct Lines l;

	if (PATH_MAX <= strlen(pkgsrepodir) + strlen(pname)
	              + strlen("//depends"))
		die("%s: PATH_MAX exceeded", argv0);
	snprintf(f, sizeof(f), "%s/%s/depends", pkgsrepodir, pname);
	l = readlines(f);

	for (i = 0; i < l.l; i++) {
		char dname[65],
		     sndfield[8];
		int nfields;

		dname[0] = '\0';
		sndfield[0] = '\0';

		if ((nfields = sscanf(l.a[i], "%64s %7s", dname,
		                      sndfield)) < 1) {
			die("%s: PACKAGE not present in one of %s's depends",
			    argv0, pname);
		}

		dname[strcspn(dname, "\n")] = '\0';
		if (PROGRAM_MAX <= strlen(dname))
			die("%s: PROGRAM_MAX exceeded", argv0);
		strncpy(deps.a[i].pname, dname, PROGRAM_MAX);
		deps.a[i].pname[65] = '\0';
		if (nfields < 2) {
			deps.a[i].runtime = 0;
		} else if (!strcmp(sndfield, "runtime")) {
			deps.a[i].runtime = 1;
		} else {
			die("%s: the second field in one of %s's depends is "
			    "something different than runtime", argv0, pname);
		}
	}
	deps.l = i;

	return deps;
}

struct Outs
packageouts(char *pname)
{
	struct Outs outs;
	size_t i;
	struct Lines l;
	char f[PATH_MAX];

	if (PATH_MAX <= strlen(pkgsrepodir) + strlen(pname)
	              + strlen("//outs"))
		die("%s: PATH_MAX exceeded");
	snprintf(f, sizeof(f), "%s/%s/outs", pkgsrepodir, pname);
	l = readlines(f);

	for (i = 0; i < l.l; i++) {
		if (l.a[i][0] == '\0') {
			die("%s: empty path found in %s's outs", argv0, pname);
		}

		if (l.a[i][0] != '/') {
			die("%s: non-absolute path found in %s's outs",
			    argv0, pname);
		}

		strncpy(outs.a[i], l.a[i], PATH_MAX);
	}
	outs.l = i;

	return outs;
}

struct Requires
packagerequires(char *pname)
{
	struct Lines l;
	char f[PATH_MAX];
	size_t i;
	struct Requires new;

	if (PATH_MAX <= strlen(pkgsrepodir) + strlen(pname)
	              + strlen("//requires"))
		die("%s: PATH_MAX exceeded", argv0);
	snprintf(f, sizeof(f), "%s/%s/requires", pkgsrepodir, pname);
	l = readlines(f);

	for (i = 0; i < l.l; i++) {
		if (l.a[i][0] == '\0') {
			die("%s: empty line found in %s's requires",
			    argv0, pname);
		}
		strncpy(new.a[i], l.a[i], PROGRAM_MAX);
	}
	new.l = i;

	return new;
}

struct SourceNode *
packagesources(char *pname)
{
	char f[PATH_MAX];
	struct Lines l;
	int i;
	struct SourceNode *tail = NULL, *head = NULL;

	if (PATH_MAX <= strlen(pkgsrepodir) + strlen(pname)
	              + strlen("//sources"))
		die("%s: PATH_MAX exceeded");
	snprintf(f, sizeof(f), "%s/%s/sources", pkgsrepodir, pname);
	l = readlines(f);

	for (i = 0; i < l.l; i++) {
		char sha256[65],
		     url[256],
		     relpath[256];
		uint8_t *sha256bin;
		int nfields;
		struct SourceNode *s = malloc(sizeof(struct SourceNode));

		sha256[0] = '\0';
		url[0] = '\0';
		relpath[0] = '\0';

		if ((nfields = sscanf(l.a[i], "%64s %255s %255s",
		                      sha256, url, relpath)) < 2) {
			free(s);
			die("%s: URL or SHA256 not present in one of %s's "
			    "sources",argv0, pname);
		}
		sha256bin = sha256chartouint8(sha256);
		memcpy(s->v.sha256, sha256bin, SHA256_DIGEST_LENGTH);
		free(sha256bin);

		url[strcspn(url, "\n")] = '\0';
		if (!relpathisvalid(url) && !urlisvalid(url)) {
			free(s);
			die("%s: URL %s is not valid", argv0, url);
		}
		if (!(s->v.url = malloc(strlen(url) + 1))) {
			free(s);
			perror("malloc");
			exit(EXIT_FAILURE);
		};
		strcpy(s->v.url, url);
		s->v.url[255] = '\0';

		if (nfields == 3) {
			relpath[strcspn(relpath, "\n")] = '\0';
			if (!relpathisvalid(relpath)) {
				free(s->v.url);
				free(s);
				die("%s: RELPATH %s is not valid",
				    argv0, relpath);
			}
			if (!(s->v.relpath = malloc(strlen(relpath) + 1))) {
				free(s->v.url);
				free(s);
				perror("malloc");
				exit(EXIT_FAILURE);
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
printinstalled(char *prefix, struct Packages pkgs)
{
	int i;

	for (i = 0; i < pkgs.l; i++) {
		if (packageisinstalled(pkgs.a[i], prefix))
			printf("%s\n", pkgs.a[i]);
	}
}

struct Lines
readlines(const char *f)
{
	struct Lines l;
	size_t i;
	FILE *fp;
	char buf[LINE_MAX];

	fp = fopen(f, "r");
	if (!fp) {
		l.l = 0;
		return l;
	};

	i = 0;
	while (fgets(buf,sizeof(buf), fp) != NULL) {
		buf[strcspn(buf, "\n")] = '\0';
		strncpy(l.a[i], buf, LINE_MAX);
		i++;
		if (i >= LINES_MAX) die("%s: LINES_MAX exceeded", argv0);
	}
	l.l = i;

	fclose(fp);
	return l;
}

unsigned int
relpathisvalid(char *relpath)
{
	return (!strstr(relpath, "..") && !strstr(relpath, ":")
	                               && relpath[0] != '/'
	                               && relpath[0] != '.');
}

uint8_t *
sha256chartouint8(const char *c)
{
	uint8_t *u;
	int i;

	if (!(u = malloc(SHA256_DIGEST_LENGTH * sizeof(uint8_t)))) {
		perror("malloc");
		exit(EXIT_FAILURE);
	}

	for (i = 0; i < SHA256_DIGEST_LENGTH; i++)
		sscanf(c + i * 2, "%2hhx", &u[i]);

	return u;
}

uint8_t *
sha256hash(const char *f)
{
	unsigned char buf[4096];
	uint8_t *res, hash[SHA256_DIGEST_LENGTH];
	size_t br;
	struct sha256 ctx;
	FILE *ff;

	sha256_init(&ctx);

	if (!(ff = fopen(f, "rb"))) {
		perror("fopen");
		exit(EXIT_FAILURE);
	}

	while ((br = fread(buf, 1, sizeof(buf), ff)) > 0)
		sha256_update(&ctx, buf, br);

	if (ferror(ff)) {
		fclose(ff);
		perror("ferror");
		exit(EXIT_FAILURE);
	}

	fclose(ff);
	sha256_sum(&ctx, hash);

	if (!(res = malloc(SHA256_DIGEST_LENGTH))) {
		perror("malloc");
		exit(EXIT_FAILURE);
	}

	memcpy(res, hash, SHA256_DIGEST_LENGTH);

	return res;
}

char *
sha256uint8tochar(const uint8_t *u)
{
	char *c;
	int i;

	if (!(c = malloc(64 * sizeof(char) + 1))) {
		perror("malloc");
		exit(EXIT_FAILURE);
	}

	for (i = 0; i < SHA256_DIGEST_LENGTH; i++)
		snprintf(&c[i * 2], 3, "%02x", u[i]);

	c[64] = '\0';

	return c;
}

void
sigcleanup()
{
	exit(EXIT_FAILURE);
}

void
uninstallpackage(char *pname, char *prefix, unsigned int rec,
                 struct Packages pkgs)
{
	struct Outs outs;
	int i;

	if (!packageisinstalled(pname, prefix)) {
		printf("+ skipping %s since it is not installed\n", pname);
		return;
	}

	for (i = 0; i < pkgs.l; i++) {
		struct Depends pdeps;

		pdeps = packagedepends(pkgs.a[i]);

		for (i = 0; i < pdeps.l; i++) {
			if (!strcmp(pdeps.a[i].pname, pname)
			    && pdeps.a[i].runtime
			    && packageisinstalled(pkgs.a[i], prefix)) {
				printf("+ skipping %s since %s depends on "
				       "it\n", pname, pkgs.a[i]);
				return;
			}
		}
	}

	printf("- uninstalling %s\n", pname);
	for (i = 0; i < outs.l; i++) {
		size_t fl = strlen(prefix) + strlen(outs.a[i]) + 2; /* / + \0 */
		char *f;

		if (!(f = malloc(fl))) {
			perror("malloc");
			exit(EXIT_FAILURE);
		}
		snprintf(f, fl, "%s/%s", prefix, outs.a[i]);

		if (!fileexists(f)) {
			free(f);
			continue;
		}

		if (remove(f)) {
			free(f);
			perror("remove");
			exit(EXIT_FAILURE);
		}

		free(f);
	}
	printf("+ uninstalled %s\n", pname);

	if (rec) {
		struct Depends deps = packagedepends(pname);

		for (i = 0; i < deps.l; i++) {
			if (!deps.a[i].runtime) continue;

			printf("+ found dependency %s for %s\n",
			       deps.a[i].pname, pname);

			if (!packageexists(deps.a[i].pname)) {
				printf("+ dependency %s does not exist\n",
				       deps.a[i].pname);
				continue;
			}

			uninstallpackage(deps.a[i].pname, prefix, rec, pkgs);
		}
	}
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

	if (getuid())
		die("%s: superuser privileges are required", argv0);

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
		struct Packages pkgs = getpackages();
		printinstalled(prefix, pkgs);
	}

	/* will not be evaluated when printinst is 1 */
	for (; *argv; argc--, argv++) {
		if (!packageexists(*argv))
			die("%s: package %s does not exist", argv0, *argv);

		if (uninstall) {
			struct Packages pkgs = getpackages();
			uninstallpackage(*argv, prefix, recuninstall, pkgs);
		} else {
			installpackage(*argv, prefix);
		}
	}

	if (expprefix) free(prefix);

	return EXIT_SUCCESS;
}
