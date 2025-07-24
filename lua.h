/* See LICENSE file for copyright and license details. */
#ifndef _LUA_H
#define _LUA_H

#include <lua.h>
#include <lauxlib.h>
#include <lualib.h>

int lua_cd(lua_State *luas);
int lua_cp(lua_State *luas);
int lua_echo(lua_State *luas);
int lua_exec(lua_State *luas);
int lua_mkdir(lua_State *luas);

#endif
