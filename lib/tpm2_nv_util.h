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
    TPMI_RH_NV_INDEX nv_index, TPM2B_NAME *precalc_nvname,
    TPM2B_NV_PUBLIC **nv_public, TPM2B_DIGEST *cp_hash, TPM2B_DIGEST *rp_hash,
    TPMI_ALG_HASH parameter_hash_algorithm, ESYS_TR shandle1, ESYS_TR shandle2,
    ESYS_TR shandle3) {

    return tpm2_nv_readpublic(context, nv_index, precalc_nvname, nv_public, 0,
        cp_hash, rp_hash, parameter_hash_algorithm, shandle1, shandle2,
        shandle3);
}

/**
 * Retrieves max NV buffer size based on the NV operation and accounting for the
 * buffers reported by the capability structures.
 * 1. If getcap fails, return TPM2_MAX_NV_BUFFER_SIZE constant
 * 2. If getcap passes AND op is NVDEFINE return TPM2_PT_NV_INDEX_MAX cap data
 * 3. if getcap passes AND op is !NVDEFINE return TPM2_PT_NV_BUFFER cap data
 *
 * @param esys_context
 *  The Enhanced System API (ESAPI) context
 * @param is_nvdefine_op
 *  Truth value to check if the NV operation is for defining NV index.
 * @return
 *  The maximum allowed NV size based on the NV operation and capability info.
 */
static inline uint16_t tpm2_nv_util_max_allowed_nv_size(
    ESYS_CONTEXT *esys_context, bool is_nvdefine_op) {

    /*
     * 1. Default size if getcap fails to report
     */
    uint16_t max_nv_size = TPM2_MAX_NV_BUFFER_SIZE;

    TPMS_CAPABILITY_DATA *cap_data = 0;
    UINT32 property = is_nvdefine_op ? TPM2_PT_FIXED : TPM2_PT_NV_BUFFER_MAX;
    UINT32 property_count = is_nvdefine_op ? TPM2_MAX_TPM_PROPERTIES : 1;
    tool_rc rc = tpm2_getcap(esys_context, TPM2_CAP_TPM_PROPERTIES, property,
        property_count, 0, &cap_data);
    bool is_getcap_op_fail = false;
    if (rc != tool_rc_success) {
        is_getcap_op_fail = true;
        goto out;
    }

    /*
     * 2. Non-NVDEFINE ops
     */
    if (!is_nvdefine_op) {
        if(cap_data->data.tpmProperties.tpmProperty[0].property ==
        TPM2_PT_NV_BUFFER_MAX ) {
            max_nv_size = cap_data->data.tpmProperties.tpmProperty[0].value;
        } else {
            /*
             * If TPM doesn't report TPM2_PT_NV_BUFFER_MAX in getcap,
             * set the default sz.
             */
            is_getcap_op_fail = true;
        }
        goto out;
    }

    /*
     * 3. NVDEFINE op
     */
    TPMS_TAGGED_PROPERTY *properties = cap_data->data.tpmProperties.tpmProperty;
    UINT32 count = cap_data->data.tpmProperties.count;
    if (!count) {
        is_getcap_op_fail = true;
        goto out;
    }

    /*
     * If TPM doesn't report TPM2_PT_NV_INDEX_MAX in getcap, set the default sz.
     */
    is_getcap_op_fail = true;
    UINT32 i;
    for (i = 0; i < count; i++) {
        if (properties[i].property == TPM2_PT_NV_INDEX_MAX) {
            max_nv_size = properties[i].value;
            is_getcap_op_fail = false;
            break;
        }
    }

out:
    free(cap_data);

    if (is_getcap_op_fail) {
        LOG_WARN("Cannot determine size from TPM properties."
                 "Setting max NV index size value to TPM2_MAX_NV_BUFFER_SIZE");
    }
    return max_nv_size;
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
 * @param bytes_read
 *  The number of bytes written to data_buffer
 * @return
 *  tool_rc indicating status.
 */
static inline tool_rc tpm2_util_nv_read(ESYS_CONTEXT *ectx,
    TPMI_RH_NV_INDEX nv_index, UINT16 size, UINT16 offset,
    tpm2_loaded_object * auth_hierarchy_obj, UINT8 **data_buffer,
    UINT16 *bytes_read, TPM2B_DIGEST *cp_hash, TPM2B_DIGEST *rp_hash,
    TPMI_ALG_HASH parameter_hash_algorithm, TPM2B_NAME *precalc_nvname,
    ESYS_TR shandle2, ESYS_TR shandle3, TPM2B_NV_PUBLIC **nv_pub_out) {

    /*
     * NVRead is not dispatched when:
     * cpHash size is non-zero and rpHash size is zero.
     */
    bool is_nvread_dispatched = (cp_hash->size && !rp_hash->size)? false : true;
    UINT16 max_data_size = 0;
    if (!is_nvread_dispatched) {
        *data_buffer = 0;
        max_data_size = size;
    }

    /*
     * Perform additional checks on the NV index size when actually dispatching
     * NVRead command.
     */
    tool_rc rc = tool_rc_success;
    if (is_nvread_dispatched) {

        max_data_size= tpm2_nv_util_max_allowed_nv_size(ectx, false);

        TPM2B_NV_PUBLIC *nv_public = NULL;
        rc = tpm2_util_nv_read_public(ectx, nv_index, 0, &nv_public, 0, 0, 0,
            ESYS_TR_NONE, ESYS_TR_NONE, ESYS_TR_NONE);
        if (rc != tool_rc_success) {
            goto out;
        }

        UINT16 data_size = nv_public->nvPublic.dataSize;
        if (nv_pub_out) {
            *nv_pub_out = nv_public;
        } else {
            free(nv_public);
        }
        /* if size is 0, assume the whole object */
        if (size == 0) {
            size = data_size;
        }

        if (offset > data_size) {
            LOG_ERR("Requested offset to read from is greater than size. offset=%u"
                    ", size=%u", offset, data_size);
            rc = tool_rc_general_error;
            goto out;
        }

        if (offset + size > data_size) {
            LOG_ERR("Requested to read more bytes than available from offset,"
                    " offset=%u, request-read-size=%u actual-data-size=%u", offset,
                    size, data_size);
            rc = tool_rc_general_error;
            goto out;
        }

        *data_buffer = malloc(data_size);
        if (!*data_buffer) {
            LOG_ERR("oom");
            rc = tool_rc_general_error;
            goto out;
        }
    }

    bool is_nv_index_data_larger_than_max_read = (size > max_data_size);
    /*
     * The cpHash will also be calculated when rpHash is not zero and command is
     * actually dispatched. So we want to make sure that if size is not
     * specified, the NV read operation defaulting to read the entire NV index,
     * must not cause cpHash buffer to be overwritten. This is becuase in such a
     * case the NV read is broken into two seperate calls due to the buffer size
     * being larger than the maximum NV read access size.
     */
    if ((cp_hash->size || rp_hash->size) &&
    is_nv_index_data_larger_than_max_read) {
        LOG_ERR("Cannot continue to avoid overwriting cpHash/rphash data in file. "
        "Make seperate tpm2_nvread calls with proper offsets specified to "
        "specify all NV index data to be read");

        rc = tool_rc_option_error;
        goto out;
    }

    bool is_auth_a_policy_session = is_nvread_dispatched &&
        tpm2_session_get_type(auth_hierarchy_obj->session) == TPM2_SE_POLICY;
    if (is_auth_a_policy_session && is_nv_index_data_larger_than_max_read) {
        LOG_ERR("Cannot continue as the policy auth session must be "
                "reinstantiated for multiple iterations of NV read. "
                "Specify a max read size of %u or specify an offset and max "
                "read size of %u", max_data_size, max_data_size);
        rc = tool_rc_option_error;
        goto out;
    }

    UINT16 data_buffer_offset = 0;
    while (size > 0) {
        UINT16 bytes_to_read = size > max_data_size ? max_data_size : size;
        TPM2B_MAX_NV_BUFFER *nv_data;
        rc = tpm2_nv_read(ectx, auth_hierarchy_obj, nv_index, precalc_nvname,
            bytes_to_read, offset, &nv_data, cp_hash, rp_hash,
            parameter_hash_algorithm, shandle2, shandle3);
        if (rc != tool_rc_success) {
            if (rc != tool_rc_option_error) {
                LOG_ERR("Failed to read NVRAM area at index 0x%X", nv_index);
            }
            goto out;
        }

        if (is_nvread_dispatched) {
            size -= nv_data->size;
            offset += nv_data->size;
            memcpy(*data_buffer + data_buffer_offset, nv_data->buffer, nv_data->size);
            data_buffer_offset += nv_data->size;
            free(nv_data);
        } else {
            /*
             * When calculating cpHash the full size is already considered and
             * so there is no need to adjust it.
             */
            size = 0;
        }
    }

    if (is_nvread_dispatched && bytes_read) {
        *bytes_read = data_buffer_offset;
    }

out:
    if (rc != tool_rc_success && *data_buffer != NULL) {
        free(*data_buffer);
        *data_buffer = NULL;
    }

    return rc;
}

static inline bool on_arg_nv_index(int argc, char **argv,
        TPMI_RH_NV_INDEX *nv_index) {

    if (argc > 1) {
        LOG_ERR("Specify single value for NV Index");
        return false;
    }

    if (!argc) {
        LOG_ERR("Specify at least a single value for NV Index");
        return false;
    }

    bool result = tpm2_util_handle_from_optarg(argv[0], nv_index,
            TPM2_HANDLE_FLAGS_NV);
    if (!result) {
        LOG_ERR("Could not convert NV index to number, got: \"%s\"", argv[0]);
        return false;
    }
    if (*nv_index == 0) {
        LOG_ERR("NV Index cannot be 0");
        return false;
    }

    return true;
}

#endif /* LIB_TPM2_NV_UTIL_H_ */
