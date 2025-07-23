/* See LICENSE file for copyright and license details. */
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

#include <lua.h>
#include <lauxlib.h>
#include <lualib.h>

int
lua_cp(lua_State *luas)
{
	const char *s = luaL_checkstring(luas, 1),
	           *d = luaL_checkstring(luas, 2);
	char buf[4096];
	size_t b;
	FILE *sf, *df;

	if (!(sf = fopen(s, "rb")))
		luaL_error(luas, "cp %s %s (fopen s): %s",
		           s, d, strerror(errno));

	if (!(df = fopen(d, "wb"))) {
		fclose(sf);
		luaL_error(luas, "cp %s %s (fopen d): %s",
		           s, d, strerror(errno));
	}

	while ((b = fread(buf, 1, sizeof(buf), sf)) > 0) fwrite(buf, 1, b, df);

	fclose(sf);
	fclose(df);

	lua_pushboolean(luas, 1);

	return 1;
}

int
lua_exec(lua_State *luas)
{
	const char *c = luaL_checkstring(luas, 1);
	int r = system(c);

	if (r == -1) {
		luaL_error(luas, "exec %s (system): %s", c, strerror(errno));
	} else {
		int s;
		if((s = WEXITSTATUS(r)))
			luaL_error(luas, "exec %s: failed with exit status %d",
			                 c, s);
	}

	lua_pushboolean(luas, 1);

	return 1;
}

int
lua_mkdir(lua_State *luas)
{
	const char *d = luaL_checkstring(luas, 1);
	int r;

	if ((r = mkdir(d, 0700)))
		luaL_error(luas, "mkdir %s: %s", d, strerror(errno));

	lua_pushboolean(luas, 1);

	return 1;
}
