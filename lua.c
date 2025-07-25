/* See LICENSE file for copyright and license details. */
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/utsname.h>
#include <sys/wait.h>
#include <unistd.h>

#include <lua.h>
#include <lauxlib.h>
#include <lualib.h>

int
lua_cd(lua_State *luas)
{
	const char *d = luaL_checkstring(luas, 1);
	if (chdir(d)) luaL_error(luas, "cd %s: %s", d, strerror(errno));
	return 0;
}

int
lua_chmod(lua_State *luas)
{
	const char *f = luaL_checkstring(luas, 1);
	mode_t m = (mode_t)luaL_checkinteger(luas, 2);
	if (chmod(f, m))
		luaL_error(luas, "chmod %s: %s", f, strerror(errno));
	return 0;
}

int
lua_cp(lua_State *luas)
{
	const char *s = luaL_checkstring(luas, 1),
	           *d = luaL_checkstring(luas, 2);
	char buf[4096], rs[PATH_MAX], rd[PATH_MAX];
	size_t b;
	FILE *sf, *df;

	if (PATH_MAX <= strlen(s) || PATH_MAX <= strlen(d))
		luaL_error(luas, "cp %s %s: PATH_MAX exceeded", s, d);
	if (!realpath(s, rs))
		luaL_error(luas, "realpath %s: %s", s, strerror(errno));
	if (!realpath(d, rd))
		luaL_error(luas, "realpath %s: %s", d, strerror(errno));

	if (!(sf = fopen(rs, "rb")))
		luaL_error(luas, "cp (%s) %s: %s", s, d, strerror(errno));

	if (!(df = fopen(rd, "wb"))) {
		fclose(sf);
		luaL_error(luas, "cp %s (%s): %s", s, d, strerror(errno));
	}

	while ((b = fread(buf, 1, sizeof(buf), sf)) > 0) fwrite(buf, 1, b, df);

	fclose(sf);
	fclose(df);

	return 0;
}

int
lua_echo(lua_State *luas)
{
	const char *s = luaL_checkstring(luas, 1);
	printf("%s\n", s);
	return 0;
}

int
lua_exec(lua_State *luas)
{
	int argc = lua_gettop(luas), i;
	char *argv[argc], cmd[PATH_MAX], *penv = getenv("PATH");
	pid_t pid;

	if (argc < 1) luaL_error(luas, "usage: exec(cmd, [arg, ...])");

	for (i = 0; i < argc; i++)
		argv[i] = (char *)luaL_checkstring(luas, i + 1);
	argv[argc] = NULL;

	if (PATH_MAX <= strlen(argv[0]))
		luaL_error(luas, "exec %s: PATH_MAX exceeded", argv[0]);
	if (argv[0][0] != '.') {
		char p[PATH_MAX], *pdir;
		if (!penv)
			luaL_error(luas, "exec %s: PATH has no values",
			           argv[0]);
		if (PATH_MAX <= strlen(penv) + strlen("/"))
			luaL_error(luas, "exec %s: PATH_MAX exceeded",
			           argv[0]);
		strncpy(p, penv, PATH_MAX);
		p[sizeof(p) - 1] = '\0';
		for (pdir = strtok(p, ":"); pdir; pdir = strtok(NULL, ":")) {
			snprintf(cmd, sizeof(cmd), "%s/%s", pdir, argv[0]);
			if (!access(cmd, X_OK)) break;
		}
		if (access(cmd, X_OK))
			luaL_error(luas, "exec %s: No such file or directory",
			           argv[0]);
	} else if (!realpath(argv[0], cmd)) {
		luaL_error(luas, "realpath %s: %s", argv[0], strerror(errno));
	}

	if ((pid = fork()) < 0) {
		luaL_error(luas, "fork: %s", argv[0], strerror(errno));
	} else if (!pid && (execvp(cmd, argv)) == -1) {
		luaL_error(luas, "exec %s: %s", argv[0], strerror(errno));
	} else {
		int s, es;
		waitpid(pid, &s, 0);
		if (WIFEXITED(s) && (es = WEXITSTATUS(s)))
			luaL_error(luas, "exec %s: failed with exit status %d",
			           argv[0], es);
	}

	return 0;
}

int
lua_getenv(lua_State *luas)
{
	const char *n = luaL_checkstring(luas, 1);
	char *v = getenv(n);
	if (v)
		lua_pushstring(luas, v);
	else
		lua_pushnil(luas);
	return 1;
}

int
lua_mkdir(lua_State *luas)
{
	const char *d = luaL_checkstring(luas, 1);
	if (mkdir(d, 0700))
		luaL_error(luas, "mkdir %s: %s", d, strerror(errno));
	return 0;
}

int
lua_setenv(lua_State *luas)
{
	const char *n = luaL_checkstring(luas, 1),
	           *v = luaL_checkstring(luas, 2);
	if (setenv(n, v, 1))
		luaL_error(luas, "setenv %s: %s", n, strerror(errno));
	return 0;
}

int
lua_uname(lua_State *luas)
{
	struct utsname u;

	if (uname(&u) < -1)
		luaL_error(luas, "uname: %s", strerror(errno));

	lua_newtable(luas);

	lua_pushstring(luas, "s");
	lua_pushstring(luas, u.sysname);
	lua_settable(luas, -3);

	lua_pushstring(luas, "n");
	lua_pushstring(luas, u.nodename);
	lua_settable(luas, -3);

	lua_pushstring(luas, "r");
	lua_pushstring(luas, u.release);
	lua_settable(luas, -3);

	lua_pushstring(luas, "v");
	lua_pushstring(luas, u.version);
	lua_settable(luas, -3);

	lua_pushstring(luas, "m");
	lua_pushstring(luas, u.machine);
	lua_settable(luas, -3);

	return 1;
}
