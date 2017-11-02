#include <string.h>

#include <linux/limits.h>
#include <unistd.h>

#include "log.h"
#include "tpm2_util.h"

int main(int argc, char *argv[]) {

    if (argc < 2) {
        LOG_ERR("Expected a tpm2 sub-command, got none!");
        return 1;
    }

    char file[PATH_MAX];

    size_t len = snprintf(file, ARRAY_LEN(file), "tpm2_%s", argv[1]);
    if (len >= ARRAY_LEN(file)) {
        LOG_ERR("tpm2 sub-command truncated!");
        return 1;
    }

    argv[1] = file;

    return execvp(file, &argv[1]);
}
