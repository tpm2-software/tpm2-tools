#include <stdbool.h>

#include <lua.h>
#include <lauxlib.h>
#include <lualib.h>

// XXX Kill off non-portable env usage.
#include <unistd.h>

#include "context-util.h"
#include "log.h"
#include "options.h"


static int isquare(lua_State *L){              /* Internal name of func */
    float rtrn = lua_tonumber(L, -1);      /* Get the single number arg */
    printf("Top of square(), nbr=%f\n",rtrn);
    lua_pushnumber(L,rtrn*rtrn);           /* Push the return */
    return 1;                              /* One return value */
}

static int icube(lua_State *L){                /* Internal name of func */
    float rtrn = lua_tonumber(L, -1);      /* Get the single number arg */
    printf("Top of cube(), number=%f\n",rtrn);
    lua_pushnumber(L,rtrn*rtrn*rtrn);      /* Push the return */
    return 1;                              /* One return value */
}

typedef struct shell_state shell_state;

struct shell_state {
    TSS2_SYS_CONTEXT *sapi_context;
    common_opts_t options;
};

static int sapi_init(lua_State *L){

    // TODO: How to pass options for selecting TCTI? Perhaps match command line and
    // parse a string here?
    // sapi_init("--tcti=xxx", "--port=yyy", ...)

    const char *tcti_name = lua_tostring(L, -1);

    shell_state *sstate = malloc(sizeof(shell_state));
    if (!sstate) {
        return luaL_error(L, "oom");
    }

    sstate->options.tcti_type = tcti_type_from_name(tcti_name),

    sstate->sapi_context = sapi_init_from_options(&sstate->options);

    printf("sstate: %p\n", sstate);

    lua_pushlightuserdata(L, sstate);

    return 1;
}

extern int execute_takeownership(int argc, const char *argv[], char *envp[], common_opts_t *opts,
        TSS2_SYS_CONTEXT *sapi_context);

static int take_ownership(lua_State *L) {

    int args = lua_gettop(L);

    if (args < 2) {
        return luaL_error(L, "Not enough arguments");
    }

    shell_state *sstate =  (shell_state *)lua_topointer(L, -2);

    printf("sstate: %p\n", sstate);

    printf("sapi_context: %p\n", sstate->sapi_context);

    int argc = args;

    printf("args_left: %d\n", args + 1);

    const char **argv= calloc(args, sizeof(char *));

    // Need to convert for unsigned...
    int i;
    argv[0] = "tpm_shell";
    for(i=1; i < argc; i++) {
        printf("building argv[%d]\n", i);
        argv[i] = lua_tostring(L, -1);
        printf("building argv with: %s\n", argv[i]);
    }

    printf("Calling execute_takeownership!");

    int rc = execute_takeownership(argc, argv, environ, &sstate->options, sstate->sapi_context);

    printf("execute_takeownership returned: %d\n", rc);

    /* return no args for now */
    return 0;
}


/* Register this file's functions with the
 * luaopen_libraryname() function, where libraryname
 * is the name of the compiled .so output. In other words
 * it's the filename (but not extension) after the -o
 * in the cc command.
 *
 * So for instance, if your cc command has -o power.so then
 * this function would be called luaopen_power().
 *
 * This function should contain lua_register() commands for
 * each function you want available from Lua.
 *
*/
int luaopen_tpm_shell(lua_State *L){
    lua_register(L, "square", isquare);
    lua_register(L,"cube", icube);
    lua_register(L,"sapi_init", sapi_init);
    lua_register(L,"take_ownership", take_ownership);
    return 0;
}
