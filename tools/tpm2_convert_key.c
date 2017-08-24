//**********************************************************************;
// Copyright (c) 2015, Intel Corporation
// All rights reserved.
//
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions are met:
//
// 1. Redistributions of source code must retain the above copyright notice,
// this list of conditions and the following disclaimer.
//
// 2. Redistributions in binary form must reproduce the above copyright notice,
// this list of conditions and the following disclaimer in the documentation
// and/or other materials provided with the distribution.
//
// 3. Neither the name of Intel Corporation nor the names of its contributors
// may be used to endorse or promote products derived from this software without
// specific prior written permission.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
// AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
// IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
// ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
// LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
// CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
// SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
// INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
// CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
// ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF
// THE POSSIBILITY OF SUCH DAMAGE.
//**********************************************************************;

#include <errno.h>
#include <limits.h>
#include <stdbool.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include <openssl/rsa.h>
#include <openssl/pem.h>

#include <getopt.h>

#include "files.h"
#include "log.h"
#include "main.h"
#include "options.h"
#include "tpm2_util.h"

/*
 * This program takes a key file as created by `tpm2_akparse` as input and
 * converts it into OpenSSL PEM or DER format public keys.
 *
 * This is currently limited to RSA public keys but might be extended to other
 * key types in the future.
 */

// holds all the custom command line parameters for our purposes
typedef struct tpm_convert_key_ctx tpm_convert_key_ctx;
struct tpm_convert_key_ctx {
    char *key_input_file_path;
    char *key_output_file_path;
    char *key_output_format;
};

// holds a single key blob as found in the input file
struct key_blob {
    UINT16 length;
    UINT8  *data;
};

#define MAX_KEY_BLOBS 8

// holds the complete information as found in the input file
struct key_data {
    UINT16 alg_type;
    size_t num_blobs;
    struct key_blob blobs[MAX_KEY_BLOBS];
};

typedef enum {
    FMT_PEM,
    FMT_DER,
    FMT_INVAL
} convert_format;

// reads just the algorithm type identifier from the given file and returns it
// in the correct endianess. error handling included.
static bool read_alg_type(FILE *f, UINT16 *alg_type) {

    if (fread(alg_type, 2, 1, f) != 1) {
        LOG_ERR("Could not read algtype from input file: \"%s\".",
            (feof(f) ? "Premature end of file" : strerror(errno))
        );

        return false;
    }

    // convert byte order
    *alg_type = tpm2_util_ntoh_16(*alg_type);

    return true;
}

// frees any dynamically allocated data in the given key_data struct
static void free_keys(struct key_data *data) {
    size_t i;
    struct key_blob *blob;

    for (i = 0; i < data->num_blobs; i++) {
        blob = &(data->blobs[i]);
        free(blob->data);
        blob->data = NULL;
    }
}
// parse all found blob parts from the given file and add them to the key_data
// struct. error handling included.
// on true return the caller is responsible for freeing data
static bool read_blobs(FILE *f, struct key_data *data) {
    const size_t MAX_LENGTH = 8192;
    struct key_blob blob;
    bool ret = false;

    // read in a variable number of blobs until EOF or error occurs
    while (true) {

        if (fread(&blob.length, 2, 1, f) != 1) {
            if (!feof(f)) {
                LOG_ERR("Could not read key blob length from input file: \"%s\".",
                    strerror(errno)
                );

                goto out;
            }

            ret = true;
            break;
        }

        // correct byte order
        blob.length = tpm2_util_ntoh_16(blob.length);

        if (blob.length > MAX_LENGTH) {
            LOG_ERR("Excess length key blob of %d bytes encountered",
                blob.length
            );

            goto out;
        }
        else if (data->num_blobs == MAX_KEY_BLOBS) {
            LOG_ERR("Maximum number of key blobs %d exceeded.", MAX_KEY_BLOBS);
            goto out;
        }

        blob.data = malloc(blob.length);

        if (fread(blob.data, blob.length, 1, f) != 1) {
            LOG_ERR("Failed to read key blob nr. %zd: \"%s\".",
                data->num_blobs + 1,
                (feof(f) ? "Premature end of file" : strerror(errno))
            );

            free(blob.data);

            goto out;
        }

        data->blobs[data->num_blobs] = blob;
        data->num_blobs ++;
    }

out:

    if (ret == false) {
        free_keys(data);
    }

    return ret;
}

/*
 * Read the binary structure from infile and put it into the given blob output
 * parameter. This expects the structure as output by tpm2_akparse.
 */
static bool read_key(const char *infile, struct key_data *data) {
    FILE *f;
    bool ret = false;

    memset(data, 0, sizeof(struct key_data));

    f = fopen(infile, "rb");
    if (!f) {
        LOG_ERR("Could not open input file \"%s\": \"%s\".",
            infile,
            strerror(errno)
        );

        return false;
    }

    if (read_alg_type(f, &data->alg_type) != true)
        goto out;
    else if (read_blobs(f, data) != true)
        goto out;

    if (data->num_blobs == 0) {
        LOG_ERR("Could not read any key blobs");
        goto out;
    }

    ret = true;

out:
    fclose(f);

    return ret;
}

// converts the information found in the key_data struct into the
// corresponding OpenSSL format, storing the result in outfile.
static bool write_key(
    const char *outfile, struct key_data *data, convert_format format) {

    FILE *f = NULL;
    bool ret = false;
    RSA *ssl_rsa_key = RSA_new();
    // openssl expects this in network byte order
    UINT32 exponent = tpm2_util_hton_32(RSA_DEFAULT_PUBLIC_EXPONENT);

    ssl_rsa_key->n = BN_bin2bn(
        (data->blobs[0]).data,
        (data->blobs[0]).length,
        NULL
    );
    ssl_rsa_key->e = BN_bin2bn(
        (void*)&exponent, sizeof(exponent), NULL
    );

    if (!ssl_rsa_key->n || !ssl_rsa_key->e) {
        LOG_ERR("Failed to convert input data to SSL internal format: \"%s\"",
            strerror(errno)
        );
        goto out;
    }

    if (files_does_file_exist(outfile)) {
        goto out;
    }

    f = fopen(outfile, "wb+");
    if (!f) {
        LOG_ERR("Could not open output file \"%s\": \"%s\".",
            outfile,
            strerror(errno)
        );
        goto out;
    }

    switch(format) {
    case FMT_PEM:
        if (PEM_write_RSA_PUBKEY(f, ssl_rsa_key) <= 0) {
            LOG_ERR("OpenSSL PEM conversion failed: \"%s\"", strerror(errno));
            goto out;
        }
        break;
    case FMT_DER:
        if (i2d_RSA_PUBKEY_fp(f, ssl_rsa_key) <= 0) {
            LOG_ERR("OpenSSL DER conversion failed: \"%s\"", strerror(errno));
            goto out;
        }
        break;
    default:
        LOG_ERR("Unexpected output format encountered");
        goto out;
    }

    ret = true;

out:
    if (f)
        fclose(f);
    RSA_free(ssl_rsa_key);
    return ret;
}

static convert_format get_format(const char *format) {

    if (strcmp(format, "PEM") == 0)
        return FMT_PEM;
    else if (strcmp(format, "DER") == 0)
        return FMT_DER;

    LOG_ERR("Invalid conversion format \"%s\" encountered", format);

    return FMT_INVAL;
}

// performs the complete program logic using the command line information
// assembled in ctx
static bool convert_key(const struct tpm_convert_key_ctx *ctx) {

    struct key_data data;
    convert_format format = get_format(ctx->key_output_format);
    bool ret = false;

    if (format == FMT_INVAL)
        return false;
    else if (! read_key(ctx->key_input_file_path, &data))
        return false;

    if (data.alg_type != TPM_ALG_RSA) {
        LOG_ERR("Unsupported algorithm type 0x%04x in input file.",
            data.alg_type
        );

        goto out;
    }
    else if (data.num_blobs != 1) {
        LOG_ERR("Unexpected number of key blobs encountered: %zd",
            data.num_blobs);

        goto out;
    }

    ret = write_key(ctx->key_output_file_path, &data, format);

out:
    free_keys(&data);

    return ret;
}

static bool init(int argc, char *argv[], tpm_convert_key_ctx *ctx) {

    struct option options[] = {
            { "keyInFile",    required_argument, NULL, 'k' },
            { "keyOutFile",   required_argument, NULL, 'f' },
            { "keyOutFormat", required_argument, NULL, 't' },
            { NULL,           no_argument,       NULL, '\0' }
    };

    if (argc <=1 || argc > (int) (2 * sizeof(options) / sizeof(struct option))) {
        showArgMismatch(argv[0]);
        return false;
    }

    int opt;
    while ((opt = getopt_long(argc, argv, "f:k:t:hv", options, NULL)) != -1) {
        switch (opt) {
        case 'f':
            if (!optarg) {
                LOG_ERR("Please specify the file containing the public key");
                return false;
            }
            ctx->key_input_file_path = optarg;
            break;
        case 'k':
            if (!optarg) {
                LOG_ERR("Please specify the file where to save the converted public key");
                return false;
            }
            ctx->key_output_file_path = optarg;
            break;
        case 't':
            if (!optarg) {
                LOG_ERR("Please specify the output file format");
                return false;
            }
            ctx->key_output_format = optarg;
            break;
        case ':':
            LOG_ERR("Argument %c needs a value!", optopt);
            return false;
        case '?':
            LOG_ERR("Unknown Argument: %c", optopt);
            return false;
        default:
            LOG_ERR("?? getopt returned character code 0%o ??", opt);
            return false;
        }
    }

    if (
        !ctx->key_input_file_path ||
        !ctx->key_output_file_path ||
        !ctx->key_output_format) {
        LOG_ERR("One or more required parameters missing.");
        return false;
    }

    return true;
}

int execute_tool(int argc, char *argv[], char *envp[], common_opts_t *opts,
        TSS2_SYS_CONTEXT *sapi_context) {

    /* opts is unused, avoid compiler warning */
    (void)opts;
    (void)sapi_context;
    (void)envp;

    struct tpm_convert_key_ctx ctx;

    memset(&ctx, 0, sizeof(struct tpm_convert_key_ctx));

    bool result = init(argc, argv, &ctx);
    if (!result) {
        return 1;
    }

    /* 0 on success, 1 on error */
    return convert_key(&ctx) == true ? 0 : 1;
}

