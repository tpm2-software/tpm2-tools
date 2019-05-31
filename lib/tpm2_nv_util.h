/* SPDX-License-Identifier: BSD-3-Clause */

#ifndef LIB_TPM2_NV_UTIL_H_
#define LIB_TPM2_NV_UTIL_H_

#include <tss2/tss2_esys.h>
#include <string.h>

#include "log.h"
#include "tpm2.h"
#include "tpm2_capability.h"
#include "tpm2_session.h"
#include "tpm2_auth_util.h"
#include "tpm2_hierarchy.h"
#include "tpm2_util.h"

/*
 * The default buffer size when one cannot be determined via get capability.
 */
#define NV_DEFAULT_BUFFER_SIZE 512

/**
 * Reads the public portion of a Non-Volatile (nv) index.
 * @param context
 *  The ESAPI context.
 * @param nv_index
 *  The index to read.
 * @param nv_public
 *  The public data structure to store the results in.
 * @return
 *  tool_rc indicating status.
 */
static inline tool_rc tpm2_util_nv_read_public(ESYS_CONTEXT *context,
        TPMI_RH_NV_INDEX nv_index, TPM2B_NV_PUBLIC **nv_public) {

    ESYS_TR tr_object;
    tool_rc rc = tpm2_from_tpm_public(context, nv_index,
                                 ESYS_TR_NONE, ESYS_TR_NONE, ESYS_TR_NONE,
                                 &tr_object);
    if (rc != tool_rc_success) {
        return rc;
    }

    rc = tpm2_nv_readpublic(context, tr_object,
                              ESYS_TR_NONE, ESYS_TR_NONE, ESYS_TR_NONE,
                              nv_public, NULL);
    tool_rc tmp_rc = tpm2_close(context, &tr_object);
    if (tmp_rc != tool_rc_success) {
        rc = tmp_rc;
    }

    return rc;
}


/**
 * Retrieves the maximum transmission size for an NV buffer by
 * querying the capabilities for TPM2_PT_NV_BUFFER_MAX.
 * @param context
 *  The Enhanced System API (ESAPI) context
 * @param size
 *  The size of the buffer.
 * @return
 *  tool_rc Indicating status.
 */
static inline tool_rc tpm2_util_nv_max_buffer_size(ESYS_CONTEXT *ectx,
        UINT32 *size) {

    /* Get the maximum read block size */
    TPMS_CAPABILITY_DATA *cap_data;
    TPMI_YES_NO more_data;
    tool_rc rc = tpm2_getcap(ectx,
                        ESYS_TR_NONE, ESYS_TR_NONE, ESYS_TR_NONE,
                        TPM2_CAP_TPM_PROPERTIES, TPM2_PT_NV_BUFFER_MAX,
                        1, &more_data, &cap_data);
    if (rc != tool_rc_success) {
        return rc;
    }

    *size = cap_data->data.tpmProperties.tpmProperty[0].value;

    free(cap_data);

    return rc;
}

/**
 * Reads data at Non-Volatile (nv) index.
 * @param ectx
 *  The ESAPI context.
 * @param nv_index
 *  The index to read.
 * @param size
 *  The number of bytes to read.
 * @param offset
 *  Offset (in bytes) from which to start reading.
 * @param hierarchy
 *  TPMI_RH_NV hierarchy value.
 * @param sdata
 *  Session authorization
 * @param sess
 *  tpm2 session.
 * @param data_buffer
 *  (callee-allocated) Buffer containing data at nv_index
 * @param bytes_written
 *  The number of bytes written to data_buffer
 * @return
 *  True on success, false otherwise.
 */
static inline bool tpm2_util_nv_read(
        ESYS_CONTEXT *ectx,
        TPMI_RH_NV_INDEX nv_index,
        UINT16 size,
        UINT16 offset,
        TPMI_RH_PROVISION hierarchy,
        tpm2_session *sess,
        UINT8 **data_buffer,
        UINT16 *bytes_written) {

    bool res = false;
    *data_buffer = NULL;

    ESYS_TR nv_handle;
    TSS2_RC rval = Esys_TR_FromTPMPublic(ectx, nv_index,
                        ESYS_TR_NONE, ESYS_TR_NONE, ESYS_TR_NONE,
                        &nv_handle);
    if (rval != TPM2_RC_SUCCESS) {
        LOG_PERR(Esys_TR_FromTPMPublic, rval);
        res = false;
        goto out;
    }

    // Don't use tpm2_util_nv_read_public since we need to make use of nv_handle
    // later
    TPM2B_NV_PUBLIC *nv_public = NULL;
    rval = Esys_NV_ReadPublic(ectx, nv_handle,
                              ESYS_TR_NONE, ESYS_TR_NONE, ESYS_TR_NONE,
                              &nv_public, NULL);
    if (rval != TSS2_RC_SUCCESS) {
        LOG_PERR(Esys_NV_ReadPublic, rval);
        res = false;
        goto out;
    }

    UINT16 data_size = nv_public->nvPublic.dataSize;
    free(nv_public);

    /* if size is 0, assume the whole object */
    if (size == 0) {
        size = data_size;
    }

    if (offset > data_size) {
        LOG_ERR(
            "Requested offset to read from is greater than size. offset=%u"
            ", size=%u", offset, data_size);
        res = false;
        goto out;
    }

    if (offset + size > data_size) {
        LOG_ERR(
            "Requested to read more bytes than available from offset,"
            " offset=%u, request-read-size=%u actual-data-size=%u",
            offset, size, data_size);
        res = false;
        goto out;
    }

    UINT32 max_data_size;
    tool_rc rc = tpm2_util_nv_max_buffer_size(ectx, &max_data_size);
    if (rc != tool_rc_success) {
        res = false;
        goto out;
    }

    if (max_data_size > TPM2_MAX_NV_BUFFER_SIZE) {
        max_data_size = TPM2_MAX_NV_BUFFER_SIZE;
    } else if (max_data_size == 0) {
        max_data_size = NV_DEFAULT_BUFFER_SIZE;
    }

    ESYS_TR tr_hierarchy;
    if (hierarchy == nv_index) {
        tr_hierarchy = nv_handle;
    } else {
        tr_hierarchy = tpm2_tpmi_hierarchy_to_esys_tr(hierarchy);
    }

    ESYS_TR shandle1 = tpm2_auth_util_get_shandle(ectx, tr_hierarchy, sess);
    if (shandle1 == ESYS_TR_NONE) {
        LOG_ERR("Couldn't get shandle for hierarchy");
        res = false;
        goto out;
    }

    *data_buffer = malloc(data_size);
    if (!*data_buffer) {
        LOG_ERR("oom");
        res = false;
        goto out;
    }

    UINT16 data_offset = 0;

    while (size > 0) {

        UINT16 bytes_to_read = size > max_data_size ? max_data_size : size;

        TPM2B_MAX_NV_BUFFER *nv_data;

        rval = Esys_NV_Read(ectx, tr_hierarchy, nv_handle,
                    shandle1, ESYS_TR_NONE, ESYS_TR_NONE,
                    bytes_to_read, offset, &nv_data);
        if (rval != TPM2_RC_SUCCESS) {
            LOG_ERR("Failed to read NVRAM area at index 0x%X", nv_index);
            LOG_PERR(Esys_NV_Read, rval);
            res = false;
            goto out;
        }

        size -= nv_data->size;
        offset += nv_data->size;

        memcpy(*data_buffer + data_offset, nv_data->buffer, nv_data->size);
        data_offset += nv_data->size;

        free(nv_data);
    }

    res = true;
    if (bytes_written) {
        *bytes_written = data_offset;
    }

out:
    if (!res && *data_buffer != NULL) {
        free(*data_buffer);
        *data_buffer = NULL;
    }

    rval = Esys_TR_Close(ectx, &nv_handle);
    if (rval != TSS2_RC_SUCCESS) {
        LOG_PERR(Esys_NV_ReadPublic, rval);
        return false;
    }

    return res;
}

#endif /* LIB_TPM2_NV_UTIL_H_ */
