/* See LICENSE file for copyright and license details. */
#include <errno.h>
#include <stdio.h>
#include <string.h>

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
