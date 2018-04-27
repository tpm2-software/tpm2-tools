//**********************************************************************;
// Copyright (c) 2017, Alibaba Group
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
#include <stdarg.h>
#include <stdbool.h>
#include <stdlib.h>

#include "log.h"
#include "tpm2_errata.h"
#include "tpm2_util.h"

struct tpm2_errata_desc {
    UINT32 spec_level;          /* spec level */
    UINT32 spec_rev;            /* spec revision */
    UINT32 errata_ver;          /* errata version */
    void (*fixup)(va_list *ap); /* errata correction handler */
    const char *name;           /* full section name in errata doc */
};

/*
 * Published spec and errata information.
 *
 * Note that TPM2_PT_YEAR and TPM2_PT_DAY_OF_YEAR retrieved
 * from capability query only have the values of the
 * release date of the specification if the TPM does not
 * implement an errata. So the spec info are also given.
 */
static struct tpm2_errata_info {
    UINT32 spec_level;
    UINT32 spec_rev;
    UINT32 errata_ver;
    UINT32 year;
    UINT32 day_of_year;
} known_errata_info[] = {
    /* Specification Revision 1.16 October 30, 2014 */
    { 00, 116, 000, 2014, 303 },
    /* Errata Version 1.2 February 16, 2015 */
    { 00, 116, 120, 2015,   4 },
    /* Errata Version 1.3 June 16, 2015 */
    { 00, 116, 130, 2015, 167 },
    /* Errata Version 1.4 January 15, 2016 */
    { 00, 116, 140, 2016,  15 },
    /* Errata Version 1.5 September 21, 2016 */
    { 00, 116, 150, 2016, 265 },
    /* Specification Revision 1.38 September 29, 2016 */
    { 00, 138, 000, 2016, 273 },
    /* Errata Version 1.0 January 16, 2017 */
    { 00, 138, 100, 2017,  16 },
    /* Errata Version 1.1 March 2, 2017 */
    { 00, 138, 110, 2017,  61 },
};

static struct tpm2_errata_info *this_errata_info;

static void fixup_sign_decrypt_attribute_encoding(va_list *ap);

/*
 * Beware of that each record contains the first errata
 * version with the corresponding correction. This rule
 * allows errata_match() to function properly.
 */
static struct tpm2_errata_desc errata_desc_list[] = {
    [SPEC_116_ERRATA_2_7] = {
        .spec_level = 00,
        .spec_rev = 116,
        .errata_ver = 120,
        .fixup = fixup_sign_decrypt_attribute_encoding,
        .name = "Sign/decrypt attribute encoding",
    },
    /*
     * Append the new errata descriptor here.
     */
};

static bool errata_match(struct tpm2_errata_desc *errata);
static struct tpm2_errata_desc *errata_query(tpm2_errata_index_t index);

/*
 * Request an errata correction.
 * @index: the errata to be queried.
 *
 * This function requests an errata correction to work
 * around a known issue well documented in errata doc.
 * If the request is valid and known, the queried errata
 * will be applied by the corresponding pre-defined errata
 * correction handler. The fixup process is transparent to
 * the callers so there is no return values. Any tools can
 * call this function to apply an errata if necessary.
 *
 * Return value:
 * N/A
 */
void tpm2_errata_fixup(tpm2_errata_index_t index, ...) {

    struct tpm2_errata_desc *errata;

    /*
     * There was no match against the TPMs details to a
     * known errata.
     */
    if (!this_errata_info) {
        return;
    }

    /* Look up what errata the caller wants us to fix. */
    errata = errata_query(index);
    if (!errata) {
        return;
    }

    /*
     * Check to see if that errata matches the tpm's
     * information and thus needs to be applied.
     */
    bool res = errata_match(errata);
    if (res == false) {
        return;
    }

    va_list ap;

    va_start(ap, index);
    errata->fixup(&ap);
    va_end(ap);

    LOG_INFO("Errata %s applied", errata->name);
}

static void process(TPMS_CAPABILITY_DATA capability_data) {
    /* Distinguish current spec level 0 */
    UINT32 spec_level = -1;
    UINT32 spec_rev = 0;
    UINT32 day_of_year = 0;
    UINT32 year = 0;
    TPML_TAGGED_TPM_PROPERTY *properties = &capability_data.data.tpmProperties;
    size_t i;
    for (i = 0; i < properties->count; ++i) {
        TPMS_TAGGED_PROPERTY *property = properties->tpmProperty + i;

        if (property->property == TPM2_PT_LEVEL) {
            spec_level = property->value;
        } else if (property->property == TPM2_PT_REVISION) {
            spec_rev = property->value;
        } else if (property->property == TPM2_PT_DAY_OF_YEAR) {
            day_of_year = property->value;
        } else if (property->property == TPM2_PT_YEAR) {
            year = property->value;
            /* Short circuit because this is the last item we need */
            break;
        } else if (property->property > TPM2_PT_YEAR) {
            break;
        }
    }

    if (!spec_rev || !day_of_year || !year) {
        LOG_WARN("Invalid TPM_SPEC parameter");
        return;
    }

    /* Determine the TPM spec and errata */
    for (i = 0; i < ARRAY_LEN(known_errata_info); ++i) {
         if (known_errata_info[i].day_of_year == day_of_year &&
             known_errata_info[i].year == year &&
             known_errata_info[i].spec_rev == spec_rev &&
             known_errata_info[i].spec_level == spec_level) {
             this_errata_info = known_errata_info + i;

             LOG_INFO("TPM_SPEC: spec level %d, spec rev %f, errata ver %f",
                      this_errata_info->spec_level,
                      (float)this_errata_info->spec_rev / 100,
                      (float)this_errata_info->errata_ver / 100);
             return;
         }
    }

    LOG_INFO("Unknown TPM_SPEC. spec_level: %d, spec_rev: 0x%x, "
            "year: %d, day_of_year: %d", spec_level, spec_rev,
            year, day_of_year);
}

void tpm2_errata_init_sapi(TSS2_SYS_CONTEXT *sapi_ctx) {

    TPMS_CAPABILITY_DATA capability_data;
    TSS2_RC rc;

    rc = Tss2_Sys_GetCapability(sapi_ctx, NULL, TPM2_CAP_TPM_PROPERTIES,
                                TPM2_PT_FIXED, TPM2_MAX_TPM_PROPERTIES, NULL,
                                &capability_data, NULL);
    if (rc != TPM2_RC_SUCCESS) {
        LOG_ERR("Failed to GetCapability: capability: 0x%x, property: 0x%x, "
                "TSS2_RC: 0x%x", TPM2_CAP_TPM_PROPERTIES, TPM2_PT_FIXED, rc);
        return;
    }

    process(capability_data);
}

void tpm2_errata_init(ESYS_CONTEXT *ctx) {

    TPMS_CAPABILITY_DATA *capability_data;
    TSS2_RC rc;

    rc = Esys_GetCapability(ctx, ESYS_TR_NONE, ESYS_TR_NONE, ESYS_TR_NONE,
                            TPM2_CAP_TPM_PROPERTIES,
                            TPM2_PT_FIXED, TPM2_MAX_TPM_PROPERTIES, NULL,
                            &capability_data);
    if (rc != TPM2_RC_SUCCESS) {
        LOG_ERR("Failed to GetCapability: capability: 0x%x, property: 0x%x, "
                "TSS2_RC: 0x%x", TPM2_CAP_TPM_PROPERTIES, TPM2_PT_FIXED, rc);
        return;
    }

    process(*capability_data);
    free(capability_data);
}

static void fixup_sign_decrypt_attribute_encoding(va_list *ap) {

    TPMA_OBJECT *attrs = va_arg(*ap, TPMA_OBJECT *);

    *attrs &= ~TPMA_OBJECT_SIGN_ENCRYPT;
}

static bool errata_match(struct tpm2_errata_desc *errata) {

    return errata->errata_ver > this_errata_info->errata_ver &&
           errata->spec_rev >= this_errata_info->spec_rev &&
           errata->spec_level == this_errata_info->spec_level;
}

static struct tpm2_errata_desc *errata_query(tpm2_errata_index_t index) {

    if ((size_t)index >= ARRAY_LEN(errata_desc_list)) {
        LOG_WARN("Invalid errata index queried: %u", (unsigned int)index);
        return NULL;
    }

    return &errata_desc_list[index];
}
