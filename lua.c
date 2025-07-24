/* See LICENSE file for copyright and license details. */
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
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
lua_cp(lua_State *luas)
{
	const char *s = luaL_checkstring(luas, 1),
	           *d = luaL_checkstring(luas, 2);
	char buf[4096];
	size_t b;
	FILE *sf, *df;

	if (!(sf = fopen(s, "rb")))
		luaL_error(luas, "cp (%s) %s: %s",
		           s, d, strerror(errno));

	if (!(df = fopen(d, "wb"))) {
		fclose(sf);
		luaL_error(luas, "cp %s (%s): %s",
		           s, d, strerror(errno));
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
	char *argv[argc];
	pid_t pid;

	if (argc < 1) luaL_error(luas, "usage: exec(cmd, [arg, ...])");

	for (i = 0; i < argc; i++)
		argv[i] = (char *)luaL_checkstring(luas, i + 1);
	argv[argc] = NULL;

	if ((pid = fork()) < 0) {
		luaL_error(luas, "fork: %s", argv[0], strerror(errno));
	} else if (!pid && (execvp(argv[0], argv)) == -1) {
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
lua_mkdir(lua_State *luas)
{
	const char *d = luaL_checkstring(luas, 1);
	int r;

	if ((r = mkdir(d, 0700)))
		luaL_error(luas, "mkdir %s: %s", d, strerror(errno));

	return 0;
}
