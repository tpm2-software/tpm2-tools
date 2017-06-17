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
            "  takeownership";

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

static int take_ownership(lua_State *L) {

    int argc;
    shell_state *sstate = NULL;

    char **argv = stack_to_argv_with_state(L, "tpm2_takeownership", &argc, &sstate);

    int rc = execute_takeownership(argc, argv, environ, &sstate->options, sstate->sapi_context);

    lua_pushnumber(L, rc);

    return 1;
}

int luaopen_tpm_shell(lua_State *L){
    lua_register(L,"help", help);
    lua_register(L,"tpm_open", tpm_open);
    lua_register(L,"tpm_close", tpm_close);
    lua_register(L,"takeownership", take_ownership);

    lua_pushstring(L, "tpm>");
    lua_setglobal(L, "_PROMPT");

    lua_print(L, "Welcome to the tpm_shell, for help, run help()");

    return 0;
}
