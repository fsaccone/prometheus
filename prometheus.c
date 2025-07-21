/* See LICENSE file for copyright and license details. */

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>

#include <lua.h>
#include <lualib.h>
#include <lauxlib.h>

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

static void copyfile(const char *s, const char *d);
static char *createtmpdir(char *pname);
static void die(const char *m, ...);
static unsigned int direxists(const char *f);
static char *expandtilde(const char *f);
static unsigned int fileexists(const char *f);
static struct StringNode *findinpath(struct StringNode *reqs);
static char *followsymlink(const char *f);
static void freedependllist(struct DependNode *n);
static void freesourcellist(struct SourceNode *n);
static void freestringllist(struct StringNode *n);
static void handlesignals(void(*hdl)(int));
static void installpackage(char *pname, char *prefix);
static struct StringNode *listdirs(const char *d);
static void mkdirrecursive(const char *d);
static unsigned int packageexists(char *pname);
static unsigned int packageisinstalled(char *pname, char *prefix);
static struct DependNode *packagedepends(char *pname);
static struct StringNode *packageouts(char *pname);
static struct StringNode *packagerequires(char *pname);
static struct SourceNode *packagesources(char *pname);
static void printinstalled(char *prefix, struct StringNode *pkgs);
static struct StringNode *readlines(const char *f);
static void sigcleanup();
static void uninstallpackage(char *pname, char *prefix, unsigned int rec,
                             struct StringNode *pkgs);
static void usage(void);

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
		perror("malloc");
		exit(EXIT_FAILURE);
	}
	snprintf(log, logl, "%s/prometheus.log", dir);
	if ((logfd = open(log, O_WRONLY | O_CREAT | O_TRUNC, 0700)) == -1) {
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

unsigned int
fileexists(const char *f)
{
	struct stat buf;
	return (!stat(f, &buf));
}

struct StringNode *
findinpath(struct StringNode *progs)
{
	struct StringNode *p, *head = NULL, *tail = NULL;
	char *path, *pathd;

	if (!(path = getenv("PATH")))
		die("%s: PATH is not set", argv0);

	for (p = progs; p; p = p->n) {
		unsigned int set = 0;

		for (pathd = strtok(path, ":"); pathd; pathd = strtok(NULL, ":")) {
			char *pp;
			size_t ppl = strlen(pathd) + strlen(p->v) + 1;
			struct StringNode *new;

			if (!(pp = malloc(ppl))) {
				perror("malloc");
				exit(EXIT_FAILURE);
			}
			snprintf(pp, ppl, "%s/%s", pathd, p->v);

			if (!fileexists(pp)) continue;
			set = 1;

			if (!(new = malloc(sizeof(struct StringNode)))) {
				perror("malloc");
				exit(EXIT_FAILURE);
			}
			if (!(new->v = malloc(ppl + 1))) {
				perror("malloc");
				exit(EXIT_FAILURE);
			}
			strcpy(new->v, pp);
			new->n = NULL;
			if (!head)
				head = new;
			else
				tail->n = new;
			tail = new;
		}

		if (!set)
			die("%s: program %s does not exist", argv0, p->v);
	}

	return head;
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
freedependllist(struct DependNode *n)
{
	while (n) {
		struct DependNode *nn = n->n;
		free(n->v.pname);
		free(n);
		n = nn;
	}
}

void
freesourcellist(struct SourceNode *n)
{
	while (n) {
		struct SourceNode *nn = n->n;
		free(n->v.url);
		free(n->v.sha256);
		free(n->v.relpath);
		free(n);
		n = nn;
	}
}

void
freestringllist(struct StringNode *n)
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
installpackage(char *pname, char *prefix)
{
	struct DependNode *deps, *dep;
	struct StringNode *o, *outs, *r, *reqs, *fr, *freqs;
	size_t bl, dbl;
	char *b, *db, *env;
	pid_t pid;

	if (packageisinstalled(pname, prefix)) {
		printf("+ skipping %s since it is already installed\n", pname);
		return;
	}

	env = createtmpdir(pname);

	deps = packagedepends(pname);
	for (dep = deps; dep; dep = dep->n) {
		printf("+ found dependency %s for %s\n", dep->v.pname, pname);
		if (!packageexists(dep->v.pname)) {
			printf("+ dependency %s does not exist\n",
			       dep->v.pname);
			continue;
		}
		installpackage(dep->v.pname, dep->v.runtime ? prefix : env);
	}
	freedependllist(deps);

	printf("- building %s\n", pname);
	
	/* / + /build.lua + \0 */
	bl = strlen(pkgsrepodir) + strlen(pname) + 12;
	b = malloc(bl);
	snprintf(b, bl, "%s/%s/build.lua", pkgsrepodir, pname);

	/* /prometheus.build.lua + \0 */
	dbl = strlen(env) + 22;
	db = malloc(dbl);
	snprintf(db, dbl, "%s/prometheus.build.lua", env);

	copyfile(b, db);
	free(b);
	free(db);

	reqs = packagerequires(pname);
	freqs = findinpath(reqs);
	for (r = reqs, fr = freqs; r && fr; r = r->n, fr = fr->n) {
		char *d;
		size_t dl = strlen(env) + strlen(r->v) + 1;
		if (!(d = malloc(dl))) {
			free(env);
			freestringllist(freqs);
			freestringllist(reqs);
			perror("malloc");
			exit(EXIT_FAILURE);
		}
		snprintf(d, dl, "%s%s", env, r->v);
		copyfile(fr->v, d);
		free(d);
	}
	freestringllist(freqs);
	freestringllist(reqs);

	if ((pid = fork()) < 0) {
		free(env);
		perror("fork");
		exit(EXIT_FAILURE);
	}

	if (!pid) {
		int logfd;
		lua_State *luas;

		if (chroot(env)) {
			free(env);
			perror("chroot");
			exit(EXIT_FAILURE);
		}

		if ((logfd = open("/prometheus.log", O_WRONLY)) == -1) {
			free(env);
			perror("open");
			exit(EXIT_FAILURE);
		}
		dup2(logfd, STDOUT_FILENO);
		dup2(logfd, STDERR_FILENO);
		close(logfd);

		if(!(luas = luaL_newstate())) {
			perror("luaL_newstate");
			exit(EXIT_FAILURE);
		}
		luaL_openlibs(luas);

		if (luaL_dofile(luas, "/prometheus.build.lua") != LUA_OK) {
			fprintf(stderr, "lua: %s\n", lua_tostring(luas, -1));
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
				       pname, env);
				free(env);
				exit(EXIT_FAILURE);
			}
			printf("+ built %s\n", pname);
		}
	}

	outs = packageouts(pname);
	for (o = outs; o; o = o->n) {
		char *s, *d;
		size_t ss = strlen(env) + strlen(o->v) + 1,
		       ds = strlen(prefix) + strlen(o->v) + 1;

		if (!(s = malloc(ss))) {
			free(env);
			freestringllist(outs);
			perror("malloc");
			exit(EXIT_FAILURE);
		}
		snprintf(s, ss, "%s%s", env, o->v);

		if (!fileexists(s)) {
			free(env);
			freestringllist(outs);
			die("%s: file %s in %s's outs in was not installed",
			    argv0, s, pname);
			free(s);
			exit(EXIT_FAILURE);
		}

		if (!(d = malloc(ds))) {
			free(s);
			free(env);
			freestringllist(outs);
			perror("malloc");
			exit(EXIT_FAILURE);
		}
		snprintf(d, ds, "%s%s", prefix, o->v);

		copyfile(s, d);
		free(s);
		free(d);
	}
	free(env);
	freestringllist(outs);
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

void
mkdirrecursive(const char *d)
{
	char buf[1024], *p = NULL;

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
	char bf[1024], of[1024], sf[1024];

	snprintf(bf, sizeof(bf), "%s/%s/build.lua", pkgsrepodir, pname);
	snprintf(of, sizeof(of), "%s/%s/outs", pkgsrepodir, pname);
	snprintf(sf, sizeof(sf), "%s/%s/sources", pkgsrepodir, pname);

	if (fileexists(bf) && fileexists(of) && fileexists(sf)) return 1;

	return 0;
}

unsigned int
packageisinstalled(char *pname, char *prefix)
{
	struct StringNode *o = packageouts(pname);

	for (; o; o = o->n) {
		size_t fl = strlen(prefix) + strlen(o->v) + 2; /* / + \0 */
		char *f = malloc(fl);
		snprintf(f, fl, "%s/%s", prefix, o->v);
		if (!fileexists(f)) {
			free(f);
			return 0;
		}
		free(f);
	}

	return 1;
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
			exit(EXIT_FAILURE);
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
	struct StringNode *ls, *l;
	char f[1024];

	snprintf(f, sizeof(f), "%s/%s/outs", pkgsrepodir, pname);
	ls = readlines(f);

	for (l = ls; l; l = l->n) {
		if (l->v[0] == '\0') {
			freestringllist(ls);
			die("%s: empty path found in %s's outs", argv0, pname);
		}

		if (l->v[0] != '/') {
			freestringllist(ls);
			die("%s: non-absolute path found in %s's outs",
			    argv0, pname);
		}
	}

	return ls;
}

struct StringNode *packagerequires(char *pname)
{
	struct StringNode *ls, *l;
	char f[1024];

	snprintf(f, sizeof(f), "%s/%s/requires", pkgsrepodir, pname);
	ls = readlines(f);

	for (l = ls; l; l = l->n) {
		if (l->v[0] == '\0') {
			freestringllist(ls);
			die("%s: empty line found in %s's requires",
			    argv0, pname);
		}
	}

	return ls;
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
			exit(EXIT_FAILURE);
		};
		strcpy(s->v.url, url);
		s->v.url[255] = '\0';

		memcpy(s->v.sha256, sha256bin, sizeof(sha256bin));

		if (nfields == 3) {
			relpath[strcspn(relpath, "\n")] = '\0';
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
printinstalled(char *prefix, struct StringNode *pkgs)
{
	struct StringNode *p;

	for (p = pkgs; p; p = p->n) {
		if (packageisinstalled(p->v, prefix))
			printf("%s\n", p->v);
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

void
sigcleanup()
{
	exit(EXIT_FAILURE);
}

void
uninstallpackage(char *pname, char *prefix, unsigned int rec,
                 struct StringNode *pkgs)
{
	struct StringNode *idep, *ideps = NULL, *pkg, *out;

	if (!packageisinstalled(pname, prefix)) {
		printf("+ skipping %s since it is not installed\n", pname);
		return;
	}

	for (pkg = pkgs; pkg; pkg = pkg->n) {
		struct DependNode *pdeps, *pd;

		pdeps = packagedepends(pkg->v);

		for (pd = pdeps; pd; pd = pd->n) {
			if (!strcmp(pd->v.pname, pname)
			    && pd->v.runtime
			    && packageisinstalled(pkg->v, prefix)) {
				printf("+ skipping %s since %s depends on "
				       "it\n", pname, pkg->v);
				freedependllist(pdeps);
				return;
			}
		}

		freedependllist(pdeps);
	}

	if (rec) {
		struct DependNode *dep, *deps = packagedepends(pname);
		struct StringNode *idepstail = NULL;

		for (dep = deps; dep; dep = dep->n) {
			struct StringNode *newidep;

			if (!dep->v.runtime) continue;

			printf("+ found dependency %s for %s\n",
			       dep->v.pname, pname);

			if (!packageexists(dep->v.pname)) {
				printf("+ dependency %s does not exist\n",
				       dep->v.pname);
				continue;
			}

			if (!(newidep = malloc(sizeof(struct StringNode)))) {
				perror("malloc");
				exit(EXIT_FAILURE);
			}
			if (!(newidep->v = malloc(strlen(dep->v.pname) + 1))) {
				free(newidep);
				perror("malloc");
				exit(EXIT_FAILURE);
			}
			strcpy(newidep->v, dep->v.pname);

			newidep->n = NULL;

			if (!ideps)
				ideps = newidep;
			else
				idepstail->n = newidep;

			idepstail = newidep;
		}

		freedependllist(deps);
	}

	printf("- uninstalling %s\n", pname);
	for (out = packageouts(pname); out; out = out->n) {
		size_t fl = strlen(prefix) + strlen(out->v) + 2; /* / + \0 */
		char *f;

		if (!(f = malloc(fl))) {
			freestringllist(ideps);
			perror("malloc");
			exit(EXIT_FAILURE);
		}
		snprintf(f, fl, "%s/%s", prefix, out->v);

		if (!fileexists(f)) {
			free(f);
			continue;
		}

		if (remove(f)) {
			free(f);
			freestringllist(ideps);
			perror("remove");
			exit(EXIT_FAILURE);
		}

		free(f);
	}
	printf("+ uninstalled %s\n", pname);

	for (idep = ideps; idep; idep = idep->n) {
		uninstallpackage(idep->v, prefix, rec, pkgs);
	}

	freestringllist(ideps);
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
		struct StringNode *pkgs = listdirs(pkgsrepodir);
		printinstalled(prefix, pkgs);
		freestringllist(pkgs);
	}

	/* will not be evaluated when printinst is 1 */
	for (; *argv; argc--, argv++) {
		if (!packageexists(*argv))
			die("%s: package %s does not exist", argv0, *argv);

		if (uninstall) {
			struct StringNode *pkgs = listdirs(pkgsrepodir);
			uninstallpackage(*argv, prefix, recuninstall, pkgs);
			freestringllist(pkgs);
		} else {
			installpackage(*argv, prefix);
		}
	}

	if (expprefix) free(prefix);

	return EXIT_SUCCESS;
}
