LOCAL_PATH := $(call my-dir)

# This project
TPM2_TPM_BASE=.
# Download from https://github.com/01org/TPM2.0-TSS
TPM2_TSS_BASE=tss

define add_tss_inlude
$(foreach d,$(1),$(LOCAL_PATH)/$(TPM2_TSS_BASE)/$(d))
endef

TSS2_CFLAGS := -DSAPI_CLIENT
# Here come the Version
TPM_CFLAGS := -DVERSION=\"0.98\" $(TSS2_CFLAGS)
TSS2_INCLUDE := $(call add_tss_inlude,include sysapi/include common)
TSS2_TEST_INCLUDE := $(TSS2_INCLUDE) $(call add_tss_inlude,test/common/sample test/tpmclient resourcemgr)
TPM_INCLUDE := $(TSS2_TEST_INCLUDE) $(call add_tss_inlude,include/tss2 include/tcti)

include $(CLEAR_VARS)
LOCAL_MODULE := libtss2
LOCAL_MODULE_TAGS := optional
LOCAL_CFLAGS := $(TSS2_CFLAGS)
LOCAL_C_INCLUDES := $(TSS2_INCLUDE)
LOCAL_SRC_FILES := $(call all-c-files-under,$(TPM2_TSS_BASE)/sysapi $(TPM2_TSS_BASE)/tcti $(TPM2_TSS_BASE)/common) \
                   $(call all-cpp-files-under,$(TPM2_TSS_BASE)/tcti $(TPM2_TSS_BASE)/common)
include $(BUILD_SHARED_LIBRARY)

include $(CLEAR_VARS)
LOCAL_MODULE := resourcemgr
LOCAL_MODULE_TAGS := optional
LOCAL_CFLAGS := $(TSS2_CFLAGS)
LOCAL_C_INCLUDES := $(TSS2_INCLUDE)
LOCAL_SRC_FILES := $(call all-c-files-under,$(TPM2_TSS_BASE)/resourcemgr)
LOCAL_SHARED_LIBRARIES := libtss2
LOCAL_MODULE_PATH := $(TARGET_OUT_OPTIONAL_EXECUTABLES)
include $(BUILD_EXECUTABLE)

# The common testing functions call the testing application, so it must be static library!
include $(CLEAR_VARS)
LOCAL_MODULE := libtss2_test
LOCAL_MODULE_TAGS := optional
LOCAL_CFLAGS := $(TSS2_CFLAGS)
LOCAL_C_INCLUDES := $(TSS2_TEST_INCLUDE)
LOCAL_SRC_FILES := $(call all-c-files-under,$(TPM2_TSS_BASE)/test/common/sample)
include $(BUILD_STATIC_LIBRARY)

define add_tss_test_tgt
 include $$(CLEAR_VARS)
 LOCAL_MODULE := $(1)
 LOCAL_MODULE_TAGS := optional
 LOCAL_CFLAGS := $$(TSS2_CFLAGS)
 LOCAL_C_INCLUDES := $$(TSS2_TEST_INCLUDE)
 LOCAL_SRC_FILES := $$(TPM2_TSS_BASE)/test/$(1)/$(1).cpp
 LOCAL_SHARED_LIBRARIES := libtss2
 LOCAL_STATIC_LIBRARIES := libtss2_test
 LOCAL_MODULE_PATH := $$(TARGET_OUT_OPTIONAL_EXECUTABLES)
 include $$(BUILD_EXECUTABLE)
endef

$(eval $(call add_tss_test_tgt,tpmtest))
$(eval $(call add_tss_test_tgt,tpmclient))

# The common source functions call the testing application, so it must be static library!
include $(CLEAR_VARS)
LOCAL_MODULE := libtpm_test
LOCAL_MODULE_TAGS := optional
LOCAL_CFLAGS := $(TPM_CFLAGS)
LOCAL_C_INCLUDES := $(TPM_INCLUDE)
LOCAL_SRC_FILES := $(TPM2_TPM_BASE)/sapi-tools/common.cpp
include $(BUILD_STATIC_LIBRARY)

define add_tpm_tgt
 include $$(CLEAR_VARS)
 LOCAL_MODULE := $(1)
 LOCAL_MODULE_TAGS := optional
 LOCAL_CFLAGS := $$(TPM_CFLAGS)
 LOCAL_C_INCLUDES := $$(TPM_INCLUDE)
 LOCAL_SRC_FILES := $$(TPM2_TPM_BASE)/sapi-tools/$(1).$(2)
 LOCAL_SHARED_LIBRARIES := libtss2
 LOCAL_STATIC_LIBRARIES := libtpm_test libtss2_test
 LOCAL_MODULE_PATH := $$(TARGET_OUT_OPTIONAL_EXECUTABLES)
 include $$(BUILD_EXECUTABLE)
endef

$(foreach name,$(wildcard $(LOCAL_PATH)/$(TPM2_TPM_BASE)/sapi-tools/tpm2_*.cpp),$(eval $(call add_tpm_tgt,$(basename $(notdir $(name))),cpp)))
