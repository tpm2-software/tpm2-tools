#include <stdbool.h>

#include <lua.h>
#include <lauxlib.h>
#include <lualib.h>

// XXX Kill off non-portable env usage.
#include <unistd.h>

#include "context-util.h"
#include "log.h"
#include "main.h"
#include "options.h"

typedef struct shell_state shell_state;
struct shell_state {
    TSS2_SYS_CONTEXT *sapi_context;
    common_opts_t options;
    char **argv;
    int argc;
};

static void shell_state_free(shell_state *s) {

    argv_free(s->argv, s->argc);
    sapi_teardown_full(s->sapi_context);
    free(s);
}

static char **argv_new(lua_State *L, int argc, char *name) {

    /*
     * argv is null terminated, ie argv[argc] == NULL
     * https://stackoverflow.com/questions/11020172/are-char-argv-arguments-in-main-null-terminated
     */
    char **argv = calloc(argc, sizeof(char *));

    if (!argv) {
        luaL_error(L, "oom");
        /* never gets here */
        return NULL;
    }

    argv[0] = strdup(name);
    if (!argv[0]) {
        free(argv);
        luaL_error(L, "oom");
        /* never gets here */
        return NULL;
    }

    return argv;
}

static char **stack_to_argv(lua_State *L, char *name, int *argc) {

    *argc = lua_gettop(L) + 1;

    char **argv = argv_new(L, *argc, name);

    int i;
    for (i=1; i < *argc; i++) {

        const char *tmp = luaL_checkstring(L, i);
        if (!tmp) {
            argv_free(argv, *argc);
            luaL_argerror (L, i - 1, "Expecting string or number");
            return NULL;
        }

        argv[i] = strdup(tmp);
        if (!argv[i]) {
            argv_free(argv, *argc);
            luaL_error (L, "oom");
            return NULL;
        }
    }

    return argv;
}

static char **stack_to_argv_with_state(lua_State *L, char *name, int *argc, shell_state **state) {

    int args = lua_gettop(L);

    if (args < 1) {
        luaL_error (L, "Got no arguments! Expecting at least the tpm "
                "descriptor from tpm_open()");
        return NULL;
    }

    luaL_checktype (L, 1, LUA_TLIGHTUSERDATA);

    *state =  (shell_state *)lua_topointer(L, 1);

    /*
     * the lightuserdata can safely be removed from the
     * stack as lua will not GC it.
     *
     * This sets the stack top to the arguments AFTER
     * the tpm descriptor.
     */
    lua_remove(L, 1);

    return stack_to_argv(L, name, argc);
}

static void lua_print(lua_State *L, const char *str) {

    lua_getglobal(L, "print");
    lua_pushstring(L, str);
    lua_pcall(L, 1, 0, 0);
    lua_pop(L, 1);
}

static int help(lua_State *L) {

    static const char *help_info =
            "-- TPM2 Shell\n"
            "Welcome to the TPM2 Lua Shell!\n"
            "This shell calls tools from the TPM2.0-tools project in a way that\n"
            "preserves context. You can call a tool by invoking its normal\n"
            "name without the tpm2_ prefix. Note that TCTI options no longer\n"
            "need to be passed to any tpm2 tools. TCTI options are handled in\n"
            "tpm_open().\n"
            "\n"
            "Example:\n"
            "  t = tpm_open(\"--tcti\", \"tabrmd\"\n"
            "  takeowbership(s, \"-c\"\n"
            "tpm_close(t)\n"
            "Current supported commands are:\n\n"
            "TCTI Manipulation:\n"
            "  tpm_open() -- opens a connection to a tpm. Uses the TCTI options.\n"
            "  tpm_close() -- closes a connection to a tpm. Pass the return of\n"
            "    tpm_open() to this.\n"
            "\n"
            "TPM Tools:\n"
            "  activatecredential\n"
            "  akparse\n"
            "  certify\n"
            "  create\n"
            "  createpolicy\n"
            "  createprimary\n"
            "  dictionarylockout\n"
            "  dump_capability\n"
            "  encryptdecrypt\n"
            "  evictcontrol\n"
            "  getpubak\n"
            "  getpubek\n"
            "  getrandom\n"
            "  hash\n"
            "  hmac\n"
            "  listpcrs\n"
            "  listpersistent\n"
            "  load\n"
            "  loadexternal\n"
            "  makecredential\n"
            "  nvdefine\n"
            "  nvlist\n"
            "  nvread\n"
            "  nvreadlock\n"
            "  nvrelease\n"
            "  nvwrite\n"
            "  quote\n"
            "  readpublic\n"
            "  rsadecrypt\n"
            "  rsaencrypt\n"
            "  sign\n"
            "  startup\n"
            "  takeownership\n"
            "  unseal\n"
            "  verifysignature\n";

    lua_print(L, help_info);

    return 0;
}

static int tpm_open(lua_State *L){

    int argc;
    char **argv = stack_to_argv(L, "tpm_open", &argc);

    /*
     * Don't clobber the old argv as the original allocation
     * still needs to be freed.
     */
    int new_argc = argc;
    char **new_argv = argv;
    common_opts_t opts;

    int rc = get_common_opts(&new_argc, &new_argv, &opts);
    if (rc) {
        /* just free the old argv */
        argv_free(argv, argc);
        return luaL_error(L, "Could not handle options!");
    }

    /*
     * whew.. made it.
     * Now free the old argv, keeping the new one as options
     * may coontain references.
     *
     * new argv should only have argv[0] aka comm name. Anything
     * else indicates an unkown option.
     */
    if (new_argc > 1) {
        argv_free(new_argv, new_argc);
        luaL_error(L, "found %d unknown options! Only pass tcti options.", new_argc - 1);
    }

    if (opts.verbose) {
        log_set_level(log_level_verbose);
    }

    /*
     * The order of malloc then sapi init helps to avoid
     * a sapi teardown on allocation failure.
     */
    shell_state *sstate = malloc(sizeof(shell_state));
    if (!sstate) {
        argv_free(argv, argc);
        return luaL_error(L, "oom");
    }

    TSS2_SYS_CONTEXT *sapi_context = sapi_init_from_options (&opts);
    if (!sapi_context) {
        argv_free(new_argv, new_argc);
        free(sstate);
        return luaL_error(L, "Could not initialize SAPI context!");
    }

    memcpy(&sstate->options, &opts, sizeof(opts));
    sstate->sapi_context = sapi_context;
    sstate->argv = new_argv;
    sstate->argc = new_argc;

    lua_pushlightuserdata(L, sstate);

    /* return 1 item on the stack */
    return 1;
}

static int tpm_close(lua_State *L) {

    int args = lua_gettop(L);
    if (args != 1) {
        return luaL_error(L, "Expected one argument, got %d", args);
    }

    luaL_checktype (L, -1, LUA_TLIGHTUSERDATA);

    shell_state *sstate =  (shell_state *)lua_topointer(L, -1);

    shell_state_free(sstate);

    return 0;
}

#define xstr(s) str(s)
#define str(s) #s

static int push_iterator(const char *key, const char *value, void *userdata) {
	lua_State *L = (lua_State *)userdata;

	lua_pushstring(L, key);
	lua_pushstring(L, value);

	/* the table is now the 3rd element from the top of the stack */
	lua_settable(L, -3);

	return 0;
}

static int handle_return(lua_State *L, int rc, tpm_table *t) {

    lua_pushnumber(L, rc);

    size_t size = tpm_table_size(t);
	lua_createtable(L, 0, size);

	tpm_table_foreach(t, push_iterator, L);

    tpm_table_free(t);

	return 2;
}

#define add_tool_with_mem_return(name) \
	static int builtin_##name(lua_State *L) { \
    \
        int argc; \
        shell_state *sstate = NULL; \
    \
        char **argv = stack_to_argv_with_state(L, "tpm2_"str(name), &argc, &sstate); \
    \
        tpm_table *t = tpm_table_new(); \
        if (!t) { \
            lua_pushnumber(L, TPM_RC_MEMORY); \
            return 1; \
        } \
    \
        int rc = shell_##name(argc, argv, environ, &sstate->options, sstate->sapi_context, t); \
    \
        return handle_return(L, rc, t); \
    }

#define add_tool(name) \
    static int builtin_##name(lua_State *L) { \
    \
        int argc; \
        shell_state *sstate = NULL; \
    \
        char **argv = stack_to_argv_with_state(L, "tpm2_"str(name), &argc, &sstate); \
    \
        int rc = shell_##name(argc, argv, environ, &sstate->options, sstate->sapi_context, NULL); \
    \
        lua_pushnumber(L, rc); \
    \
        return 1; \
    }

add_tool(activatecredential)
add_tool(akparse)
add_tool(certify)
add_tool(create)
add_tool_with_mem_return(createpolicy)
add_tool(createprimary)
add_tool(dictionarylockout)
add_tool(dump_capability)
add_tool(encryptdecrypt)
add_tool(evictcontrol)
add_tool(getpubak)
add_tool(getpubek)
add_tool_with_mem_return(getrandom)
add_tool(hash)
add_tool(hmac)
add_tool(listpcrs)
add_tool(listpersistent)
add_tool(load)
add_tool(loadexternal)
add_tool(makecredential);
add_tool(nvdefine);
add_tool(nvlist);
add_tool(nvread);
add_tool(nvreadlock);
add_tool(nvrelease);
add_tool(nvwrite);
add_tool(quote);
add_tool(readpublic);
add_tool(rsadecrypt);
add_tool(rsaencrypt);
add_tool(sign);
add_tool(startup);
add_tool(takeownership)
add_tool(unseal);
add_tool(verifysignature);

#define LUA_REGISTER(name) \
		lua_register(L,str(name), builtin_##name)

int luaopen_tpm_shell(lua_State *L){
    lua_register(L,"help", help);
    lua_register(L,"tpm_open", tpm_open);
    lua_register(L,"tpm_close", tpm_close);

    LUA_REGISTER(activatecredential);
    LUA_REGISTER(akparse);
    LUA_REGISTER(certify);
    LUA_REGISTER(create);
    LUA_REGISTER(createpolicy);
    LUA_REGISTER(createprimary);
    LUA_REGISTER(dictionarylockout);
    LUA_REGISTER(dump_capability);
    LUA_REGISTER(encryptdecrypt);
    LUA_REGISTER(evictcontrol);
    LUA_REGISTER(getpubak);
    LUA_REGISTER(getpubek);
    LUA_REGISTER(getrandom);
    LUA_REGISTER(hash);
    LUA_REGISTER(hmac);
    LUA_REGISTER(listpcrs);
    LUA_REGISTER(listpersistent);
    LUA_REGISTER(load);
    LUA_REGISTER(loadexternal);
    LUA_REGISTER(makecredential);
    LUA_REGISTER(nvdefine);
    LUA_REGISTER(nvlist);
    LUA_REGISTER(nvread);
    LUA_REGISTER(nvreadlock);
    LUA_REGISTER(nvrelease);
    LUA_REGISTER(nvwrite);
    LUA_REGISTER(quote);
    LUA_REGISTER(readpublic);
    LUA_REGISTER(rsadecrypt);
    LUA_REGISTER(rsaencrypt);
    LUA_REGISTER(sign);
    LUA_REGISTER(startup);
    LUA_REGISTER(takeownership);
    LUA_REGISTER(unseal);
    LUA_REGISTER(verifysignature);

    lua_pushstring(L, "tpm>");
    lua_setglobal(L, "_PROMPT");

    lua_print(L, "Welcome to the tpm_shell, for help, run help()");

    return 0;
}
