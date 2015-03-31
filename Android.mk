ifeq ($(BOARD_USES_MRST_OMX),true)

LOCAL_PATH := $(call my-dir)
include $(CLEAR_VARS)

VENDORS_INTEL_MRST_COMPONENTS_ROOT := $(LOCAL_PATH)

#intel video codecs
include $(VENDORS_INTEL_MRST_COMPONENTS_ROOT)/videocodec/Android.mk
ifneq ($(ENABLE_IMG_GRAPHICS),)
include $(VENDORS_INTEL_MRST_COMPONENTS_ROOT)/videocodec/libvpx_internal/Android.mk
endif

endif #BOARD_USES_MRST_OMX
