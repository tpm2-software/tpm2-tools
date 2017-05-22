LOCAL_PATH:= $(call my-dir)

###################################
include $(CLEAR_VARS)

LOCAL_MODULE := libtpm2.0-tools-common
LOCAL_MODULE_TAGS := optional
LOCAL_C_INCLUDES := $(LOCAL_PATH)/../TPM2.0-TSS/include
LOCAL_SRC_FILES := $(subst $(LOCAL_PATH)/,, $(wildcard $(LOCAL_PATH)/lib/*.c))

include $(BUILD_STATIC_LIBRARY)

define add_tool_executable
    include $(CLEAR_VARS)
    LOCAL_C_INCLUDES := $(LOCAL_PATH)/lib $(LOCAL_PATH)/../TPM2.0-TSS/include
    LOCAL_MODULE_TAGS := optional
    LOCAL_MODULE := $(basename $1)
    ifneq ($1,tools/tpm2_rc_decode.c)
        LOCAL_SRC_FILES := $1 tools/main.c
    else
        LOCAL_SRC_FILES := $1
    endif
    LOCAL_CFLAGS := -DHAVE_TCTI_DEV -DVERSION=\"$(shell git -C $(LOCAL_PATH) describe --tags --always --dirty)\"
    LOCAL_SHARED_LIBRARIES := libtss2.0 libtcti_device libcurl libcrypto libssl
    LOCAL_STATIC_LIBRARIES := libtpm2.0-tools-common
    include $(BUILD_EXECUTABLE)
endef


LOCAL_DONT_BUILD := tools/tpm2_getmanufec.c
LOCAL_TOOLS := $(filter-out $(LOCAL_DONT_BUILD), $(subst $(LOCAL_PATH)/,, $(wildcard $(LOCAL_PATH)/tools/tpm2_*.c)))

$(foreach item,$(LOCAL_TOOLS),$(eval $(call add_tool_executable,$(item))))
