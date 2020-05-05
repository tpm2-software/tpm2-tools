/* SPDX-License-Identifier: BSD-3-Clause */

#include <errno.h>
#include <inttypes.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <signal.h>
#include <unistd.h>

#include <arpa/inet.h>
#include <netinet/in.h>

#include <sys/types.h>
#include <sys/socket.h>

#include <tss2/tss2_tcti_network.h>

#include "files.h"
#include "log.h"
#include "tpm2_header.h"
#include "tpm2_tool.h"

typedef struct tpm2_netlisten_ctx tpm2_netlisten_ctx;
struct tpm2_netlisten_ctx {
    const char *conf;
    int pipefd[2];
};

static tpm2_netlisten_ctx ctx;

static void sighandler(int sig) {
    UNUSED(sig);

    LOG_INFO("Signal handler enter");

    ssize_t wrote = write(ctx.pipefd[1], "X", 1);

    LOG_INFO("Signal handler write %zd bytes to fd: %d\n",
            wrote, ctx.pipefd[1]);
}

static bool on_args(int argc, char **argv) {

    if (argc > 1) {
        LOG_ERR("Expected 1 tpm buffer input file, got: %d", argc);
        return false;
    }

    ctx.conf = argv[0];

    return true;
}

bool tpm2_tool_onstart(tpm2_options **opts) {

    static const struct option topts[] = {
        { "output", required_argument, NULL, 'o' },
    };

    *opts = tpm2_options_new("o:", ARRAY_LEN(topts), topts, NULL, on_args,
            0);

    return *opts != NULL;
}

tool_rc tpm2_tool_onrun(ESYS_CONTEXT *context, tpm2_option_flags flags) {

    UNUSED(flags);

    size_t nfds = 2;
    TSS2_TCTI_POLL_HANDLE poll_handles[3] = { 0 };

    tool_rc rc = tool_rc_general_error;

    signal(SIGINT, sighandler);

    size_t size = 0;
    TSS2_TCTI_CONTEXT *source_tcti = NULL;
    TSS2_RC rval = Tss2_Tcti_Network_Init (
        NULL,
        &size,
        NULL);
    if (rval != TPM2_RC_SUCCESS) {
        LOG_PERR(Esys_GetTctiContext, rval);
        rc = tool_rc_from_tpm(rval);
        goto out;
    }

    source_tcti = calloc(1, size);
    if (!source_tcti) {
        LOG_ERR("oom");
        goto out;
    }

    rval = Tss2_Tcti_Network_Server_Init (
        source_tcti,
        &size,
        ctx.conf);
    if (rval != TPM2_RC_SUCCESS) {
        LOG_PERR(Esys_GetTctiContext, rval);
        rc = tool_rc_from_tpm(rval);
        goto out;
    }

    TSS2_TCTI_CONTEXT *sink_tcti;
    rval = Esys_GetTcti(context, &sink_tcti);
    if (rval != TPM2_RC_SUCCESS) {
        LOG_PERR(Esys_GetTctiContext, rval);
        rc = tool_rc_from_tpm(rval);
        goto out;
    }

    int rx = pipe(ctx.pipefd);
    if (rx < 0) {
        LOG_ERR("pipe failed: %s", strerror(errno));
        goto out;
    }

    rval = Tss2_Tcti_GetPollHandles (
        source_tcti,
        poll_handles,
        &nfds);
    if (rval != TPM2_RC_SUCCESS) {
        LOG_PERR(Esys_GetTctiContext, rval);
        rc = tool_rc_from_tpm(rval);
        goto out;
    }

    if (nfds != 1) {
        LOG_ERR("Expected Network TCTI to only return 1 poll fd, got: %zu",
                nfds);
        goto out;
    }

    rx = listen(poll_handles[0].fd, 1);
    if(rx < 0) {
        LOG_ERR("listen failed: %s", strerror(errno));
        goto out;
    }

    poll_handles[1].fd = ctx.pipefd[0];
    nfds++;

    bool quit = false;

    while (!quit) {

        LOG_INFO("sleeping...");

        poll_handles[0].events =
                poll_handles[1].events = POLLIN;
        rx = poll(poll_handles, nfds, -1);
        if (rx < 0) {
            if (errno == EINTR) {
                LOG_INFO("poll: EINTR");
                continue;
            }
            LOG_ERR("Error occurred in poll: %s", strerror(errno));
            break;
        }

        LOG_INFO("rise and shine");

        /* exit fd */
        if (poll_handles[1].revents & POLLIN) {

            LOG_INFO("Got POLLIN event from pipefd, quit: %d\n", quit);

            char buf = '\0';
            ssize_t bytes_read = read(ctx.pipefd[0], &buf, sizeof(buf));
            if (bytes_read < 0) {
                LOG_ERR("Could not get byte from pipe: %s", strerror(errno));
                quit = 1;
                continue;
            }

            LOG_INFO("Got POLLIN event from pipefd: %c\n", buf);

            if (buf == 'X') {
                LOG_INFO("Got exit event");
                quit = 1;
                continue;
            } else {
                LOG_WARN("Unknown event: %c, ignoring.", buf);
            }
            continue;
        }

        /* accept new client */
        if (poll_handles[0].revents & POLLIN) {
            LOG_INFO("Pending client accept");
            int client_fd = accept(poll_handles[0].fd, (struct sockaddr*)NULL, NULL);
            if (client_fd < 0) {
                LOG_ERR("Error in accepting client: %s", strerror(errno));
                continue;
            }
            nfds = 3;
            poll_handles[2].fd = client_fd;
            poll_handles[2].events = POLLIN;
            continue;
        }

        printf("poll_handles[2].revents: %d\n", poll_handles[2].revents);

        /* must be more client data */
        int client_fd = poll_handles[2].fd;

        size_t rsize = TPM2_MAX_SIZE;
        UINT8 rbuf[TPM2_MAX_SIZE];

        /* get from the network */
       ssize_t bytes_read = read(client_fd, rbuf, rsize);
        if (bytes_read < 0) {
            LOG_ERR("read failed: %s", strerror(errno));
            close(client_fd);
            nfds = 2;
            client_fd = -1;
            memset(&poll_handles[2], 0, sizeof(poll_handles[2]));
            continue;
        }

        if (!bytes_read) {
            LOG_WARN("Got 0 bytes, terminating client");
            close(client_fd);
            nfds = 2;
            client_fd = -1;
            memset(&poll_handles[2], 0, sizeof(poll_handles[2]));
            continue;
        }

        /* Send to TPM */
        rval = Tss2_Tcti_Transmit(sink_tcti, bytes_read, rbuf);
        if (rval != TPM2_RC_SUCCESS) {
            LOG_PERR(Tss2_Tcti_Transmit, rval);
            close(client_fd);
            nfds = 2;
            client_fd = -1;
            memset(&poll_handles[2], 0, sizeof(poll_handles[2]));
            continue;
        }

        /* block waiting on TPM */
        rsize = sizeof(rbuf);
        rval = Tss2_Tcti_Receive(sink_tcti, &rsize, rbuf,
                TSS2_TCTI_TIMEOUT_BLOCK);
        if (rval != TPM2_RC_SUCCESS) {
            LOG_PERR(Tss2_Tcti_Receive, rval);
            close(client_fd);
            nfds = 2;
            client_fd = -1;
            memset(&poll_handles[2], 0, sizeof(poll_handles[2]));
            continue;
        }

        /* Send to Client */
        ssize_t bytes_wrote = write(client_fd, rbuf, rsize);
        if (bytes_wrote < 0) {
            LOG_ERR("write failed: %s", strerror(errno));
            close(client_fd);
            nfds = 2;
            client_fd = -1;
            memset(&poll_handles[2], 0, sizeof(poll_handles[2]));
        }

        /* loop up waiting for condition of a new client, new data or an exit */
    }

    rc = tool_rc_success;

out:
    if (poll_handles[1].fd) {
        close (poll_handles[1].fd);
    }
    Tss2_Tcti_Finalize(source_tcti);

    return rc;
}
