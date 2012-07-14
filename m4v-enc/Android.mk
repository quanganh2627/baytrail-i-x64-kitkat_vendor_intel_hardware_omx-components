ifeq ($(strip $(BOARD_USES_WRS_OMXIL_CORE)),true)
LOCAL_PATH := $(call my-dir)
include $(CLEAR_VARS)

LOCAL_SRC_FILES := \
	psb_m4v.cpp

LOCAL_MODULE_TAGS := optional
LOCAL_MODULE := libwrs_omxil_intel_mrst_psb_m4v_enc

LOCAL_CPPFLAGS := -DMIXVIDEO_ENCODE_ENABLE=0

LOCAL_LDFLAGS :=

LOCAL_STATIC_LIBRARIES :=

LOCAL_SHARED_LIBRARIES := \
	libwrs_omxil_common \
	liblog \
	libmixcommon \
	libmixvideo \
	libmixvbp \
	libva \
	libva-android \
	libva-tpi \
        libutils \
        libsharedbuffer

VENDORS_INTEL_MRST_MIXVBP_ROOT := $(VENDORS_INTEL_MRST_LIBMIX_ROOT)/mix_vbp

LOCAL_C_INCLUDES := \
	$(TARGET_OUT_HEADERS)/khronos/openmax \
	$(TARGET_OUT_HEADERS)/wrs_omxil_core \
	$(TARGET_OUT_HEADERS)/libmixcommon \
	$(TARGET_OUT_HEADERS)/libmixvideo \
	$(TARGET_OUT_HEADERS)/libva \
	$(TARGET_OUT_HEADERS)/libdrm \
	$(TARGET_OUT_HEADERS)/libdrm/shared-core \
	$(TARGET_OUT_HEADERS)/libmixvbp \
	$(TARGET_OUT_HEADERS)/libpsb_drm \
        $(TARGET_OUT_HEADERS)/libsharedbuffer


LOCAL_COPY_HEADERS_TO := libwrs_omxil_intel_mrst_psb_m4v_enc
LOCAL_COPY_HEADERS := vabuffer.h 

ifeq ($(ENABLE_BUFFER_SHARE_MODE),true)
LOCAL_CPPFLAGS += -DENABLE_BUFFER_SHARE_MODE=1
endif

include $(BUILD_SHARED_LIBRARY)
endif
