ifeq ($(strip $(BOARD_USES_WRS_OMXIL_CORE)),true)
LOCAL_PATH := $(call my-dir)

ifeq ($(TARGET_DEVICE),mfld_gi)
LOCAL_C_FLAGS := -DMFLD_GI
else ifneq (,$(findstring $(TARGET_DEVICE),mfld_dv10 redridge salitpa))
LOCAL_C_FLAGS := -DMFLD_DV10
else ifneq (,$(findstring $(TARGET_DEVICE),victoriabay ctp_pr1 ctp_nomodem))
LOCAL_C_FLAGS := -DCLVT
else ifeq ($(TARGET_DEVICE), mrfl_vp)
LOCAL_C_FLAGS := -DMRFL_VP
else ifeq ($(TARGET_DEVICE),yukkabeach)
LOCAL_C_FLAGS := -DYUKKA
else
LOCAL_C_FLAGS := -DMFLD_PR2
endif

include $(CLEAR_VARS)

LOCAL_CPPFLAGS :=
LOCAL_LDFLAGS :=

LOCAL_SHARED_LIBRARIES := \
    libwrs_omxil_common \
    libva_videodecoder \
    liblog \
    libva \
    libva-android

LOCAL_C_INCLUDES := \
    $(TARGET_OUT_HEADERS)/wrs_omxil_core \
    $(TARGET_OUT_HEADERS)/khronos/openmax \
    $(PV_INCLUDES) \
    $(TARGET_OUT_HEADERS)/libmix_videodecoder \
    $(TARGET_OUT_HEADERS)/libva \
    $(TOP)/frameworks/native/include/media/hardware \
    $(TOP)/frameworks/native/include/media/openmax

LOCAL_SRC_FILES := \
    OMXComponentCodecBase.cpp\
    OMXVideoDecoderBase.cpp\
    OMXVideoDecoderAVC.cpp

LOCAL_MODULE_TAGS := optional
LOCAL_MODULE := libOMXVideoDecoderAVC
CTP_PRODUCT := \
        ctp_pr1 \
        ctp_nomodem \
        redhookbay
ifneq ($(filter $(TARGET_PRODUCT),$(CTP_PRODUCT)),)
LOCAL_CFLAGS += -DVED_TILING
endif

include $(BUILD_SHARED_LIBRARY)


include $(CLEAR_VARS)

LOCAL_CPPFLAGS :=
LOCAL_LDFLAGS :=

LOCAL_SHARED_LIBRARIES := \
    libwrs_omxil_common \
    libva_videodecoder \
    liblog \
    libva \
    libva-android

LOCAL_C_INCLUDES := \
    $(TARGET_OUT_HEADERS)/wrs_omxil_core \
    $(TARGET_OUT_HEADERS)/khronos/openmax \
    $(PV_INCLUDES) \
    $(TARGET_OUT_HEADERS)/libmix_videodecoder \
    $(TARGET_OUT_HEADERS)/libva \
    $(TOP)/frameworks/native/include/media/hardware \
    $(TOP)/frameworks/native/include/media/openmax

LOCAL_SRC_FILES := \
    OMXComponentCodecBase.cpp\
    OMXVideoDecoderBase.cpp\
    OMXVideoDecoderMPEG4.cpp

LOCAL_MODULE_TAGS := optional
LOCAL_MODULE := libOMXVideoDecoderMPEG4
CTP_PRODUCT := \
        ctp_pr1 \
        ctp_nomodem \
        redhookbay
ifneq ($(filter $(TARGET_PRODUCT),$(CTP_PRODUCT)),)
LOCAL_CFLAGS += -DVED_TILING
endif

include $(BUILD_SHARED_LIBRARY)

include $(CLEAR_VARS)

LOCAL_CPPFLAGS :=
LOCAL_LDFLAGS :=

LOCAL_SHARED_LIBRARIES := \
    libwrs_omxil_common \
    libva_videodecoder \
    liblog \
    libva \
    libva-android

LOCAL_C_INCLUDES := \
    $(TARGET_OUT_HEADERS)/wrs_omxil_core \
    $(TARGET_OUT_HEADERS)/khronos/openmax \
    $(PV_INCLUDES) \
    $(TARGET_OUT_HEADERS)/libmix_videodecoder \
    $(TARGET_OUT_HEADERS)/libva \
    $(TOP)/frameworks/native/include/media/hardware \
    $(TOP)/frameworks/native/include/media/openmax

LOCAL_SRC_FILES := \
    OMXComponentCodecBase.cpp\
    OMXVideoDecoderBase.cpp\
    OMXVideoDecoderH263.cpp

LOCAL_MODULE_TAGS := optional
LOCAL_MODULE := libOMXVideoDecoderH263
CTP_PRODUCT := \
        ctp_pr1 \
        ctp_nomodem \
        redhookbay
ifneq ($(filter $(TARGET_PRODUCT),$(CTP_PRODUCT)),)
LOCAL_CFLAGS += -DVED_TILING
endif

include $(BUILD_SHARED_LIBRARY)


include $(CLEAR_VARS)

LOCAL_CPPFLAGS :=
LOCAL_LDFLAGS :=

LOCAL_SHARED_LIBRARIES := \
    libwrs_omxil_common \
    libva_videodecoder \
    liblog \
    libva \
    libva-android

LOCAL_C_INCLUDES := \
    $(TARGET_OUT_HEADERS)/wrs_omxil_core \
    $(TARGET_OUT_HEADERS)/khronos/openmax \
    $(PV_INCLUDES) \
    $(TARGET_OUT_HEADERS)/libmix_videodecoder \
    $(TARGET_OUT_HEADERS)/libva \
    $(TOP)/frameworks/native/include/media/hardware \
    $(TOP)/frameworks/native/include/media/openmax

LOCAL_SRC_FILES := \
    OMXComponentCodecBase.cpp\
    OMXVideoDecoderBase.cpp\
    OMXVideoDecoderWMV.cpp

LOCAL_MODULE_TAGS := optional
LOCAL_MODULE := libOMXVideoDecoderWMV
CTP_PRODUCT := \
        ctp_pr1 \
        ctp_nomodem \
        redhookbay
ifneq ($(filter $(TARGET_PRODUCT),$(CTP_PRODUCT)),)
LOCAL_CFLAGS += -DVED_TILING
endif

include $(BUILD_SHARED_LIBRARY)

include $(CLEAR_VARS)

LOCAL_CPPFLAGS :=
LOCAL_LDFLAGS :=

LOCAL_SHARED_LIBRARIES := \
        libwrs_omxil_common \
        liblog \
        libva_videoencoder \
        libva \
        libva-android \
        libva-tpi \
        libutils \
        libhardware \
        libintelmetadatabuffer

LOCAL_C_INCLUDES := \
    $(TARGET_OUT_HEADERS)/wrs_omxil_core \
    $(TARGET_OUT_HEADERS)/khronos/openmax \
    $(TARGET_OUT_HEADERS)/libmix_videoencoder \
    $(TARGET_OUT_HEADERS)/libva	\
    $(TARGET_OUT_HEADERS)/libsharedbuffer \
    $(TOP)/hardware/libhardware/include \
    $(TOP)/frameworks/native/include/media/hardware \
    $(TOP)/frameworks/native/include/media/openmax \
    $(TARGET_OUT_HEADERS)/pvr

LOCAL_SRC_FILES := \
    OMXComponentCodecBase.cpp \
    OMXVideoEncoderBase.cpp \
    OMXVideoEncoderAVC.cpp

LOCAL_CFLAGS += $(LOCAL_C_FLAGS)
ifeq ($(ENABLE_MRFL_GRAPHICS),true)
LOCAL_CFLAGS += -DMRFLD_OMX
endif

LOCAL_MODULE_TAGS := optional
LOCAL_MODULE := libOMXVideoEncoderAVC
include $(BUILD_SHARED_LIBRARY)


include $(CLEAR_VARS)

LOCAL_CPPFLAGS :=
LOCAL_LDFLAGS :=

LOCAL_SHARED_LIBRARIES := \
        libwrs_omxil_common \
        liblog \
        libva_videoencoder \
        libva \
        libva-android \
        libva-tpi \
        libutils \
        libhardware \
        libintelmetadatabuffer

LOCAL_C_INCLUDES := \
    $(TARGET_OUT_HEADERS)/wrs_omxil_core \
    $(TARGET_OUT_HEADERS)/khronos/openmax \
    $(TARGET_OUT_HEADERS)/libmix_videoencoder \
    $(TARGET_OUT_HEADERS)/libva	\
    $(TARGET_OUT_HEADERS)/libsharedbuffer \
    $(TOP)/hardware/libhardware/include \
    $(TOP)/frameworks/native/include/media/hardware \
    $(TOP)/frameworks/native/include/media/openmax \
    $(TARGET_OUT_HEADERS)/pvr

LOCAL_SRC_FILES := \
    OMXComponentCodecBase.cpp \
    OMXVideoEncoderBase.cpp \
    OMXVideoEncoderH263.cpp

LOCAL_CFLAGS += $(LOCAL_C_FLAGS)
ifeq ($(ENABLE_MRFL_GRAPHICS),true)
LOCAL_CFLAGS += -DMRFLD_OMX
endif

LOCAL_MODULE_TAGS := optional
LOCAL_MODULE := libOMXVideoEncoderH263
include $(BUILD_SHARED_LIBRARY)

include $(CLEAR_VARS)

LOCAL_CPPFLAGS :=
LOCAL_LDFLAGS :=

LOCAL_SHARED_LIBRARIES := \
        libwrs_omxil_common \
        liblog \
        libva_videoencoder \
        libva \
        libva-android \
        libva-tpi \
        libutils \
        libhardware \
        libintelmetadatabuffer

LOCAL_C_INCLUDES := \
    $(TARGET_OUT_HEADERS)/wrs_omxil_core \
    $(TARGET_OUT_HEADERS)/khronos/openmax \
    $(TARGET_OUT_HEADERS)/libmix_videoencoder \
    $(TARGET_OUT_HEADERS)/libva	\
    $(TARGET_OUT_HEADERS)/libsharedbuffer \
    $(TOP)/hardware/libhardware/include \
    $(TOP)/frameworks/native/include/media/hardware \
    $(TOP)/frameworks/native/include/media/openmax \
    $(TARGET_OUT_HEADERS)/pvr

LOCAL_SRC_FILES := \
    OMXComponentCodecBase.cpp \
    OMXVideoEncoderBase.cpp \
    OMXVideoEncoderMPEG4.cpp

LOCAL_CFLAGS += $(LOCAL_C_FLAGS)
ifeq ($(ENABLE_MRFL_GRAPHICS),true)
LOCAL_CFLAGS += -DMRFLD_OMX
endif

LOCAL_MODULE_TAGS := optional
LOCAL_MODULE := libOMXVideoEncoderMPEG4
include $(BUILD_SHARED_LIBRARY)

include $(CLEAR_VARS)

LOCAL_CPPFLAGS :=
LOCAL_LDFLAGS :=

LOCAL_SHARED_LIBRARIES := \
    libwrs_omxil_common \
    libva_videodecoder \
    liblog \
    libva \
    libva-android

LOCAL_C_INCLUDES := \
    $(TARGET_OUT_HEADERS)/wrs_omxil_core \
    $(TARGET_OUT_HEADERS)/khronos/openmax \
    $(PV_INCLUDES) \
    $(TARGET_OUT_HEADERS)/libmix_videodecoder \
    $(TARGET_OUT_HEADERS)/libva \
    $(TOP)/frameworks/native/include/media/hardware \
    $(TOP)/frameworks/native/include/media/openmax

LOCAL_SRC_FILES := \
    OMXComponentCodecBase.cpp\
    OMXVideoDecoderBase.cpp\
    OMXVideoDecoderPAVC.cpp

LOCAL_MODULE_TAGS := optional
LOCAL_MODULE := libOMXVideoDecoderPAVC
CTP_PRODUCT := \
        ctp_pr1 \
        ctp_nomodem \
        redhookbay
ifneq ($(filter $(TARGET_PRODUCT),$(CTP_PRODUCT)),)
LOCAL_CFLAGS += -DVED_TILING
endif

include $(BUILD_SHARED_LIBRARY)

include $(CLEAR_VARS)

LOCAL_CPPFLAGS :=
LOCAL_LDFLAGS :=

LOCAL_SHARED_LIBRARIES := \
        libwrs_omxil_common \
        liblog \
        libva_videoencoder \
        libva \
        libva-android \
        libva-tpi \
        libutils \
        libhardware \
        libintelmetadatabuffer

LOCAL_C_INCLUDES := \
    $(TARGET_OUT_HEADERS)/wrs_omxil_core \
    $(TARGET_OUT_HEADERS)/khronos/openmax \
    $(TARGET_OUT_HEADERS)/libmix_videoencoder \
    $(TARGET_OUT_HEADERS)/libva	\
    $(TARGET_OUT_HEADERS)/libsharedbuffer \
    $(TOP)/hardware/libhardware/include \
    $(TOP)/frameworks/native/include/media/hardware \
    $(TOP)/frameworks/native/include/media/openmax \
    $(TARGET_OUT_HEADERS)/pvr

LOCAL_SRC_FILES := \
    OMXComponentCodecBase.cpp \
    OMXVideoEncoderBase.cpp \
    OMXVideoEncoderVP8.cpp

LOCAL_MODULE_TAGS := optional
LOCAL_MODULE := libOMXVideoEncoderVP8
include $(BUILD_SHARED_LIBRARY)

include $(CLEAR_VARS)

LOCAL_CPPFLAGS :=
LOCAL_LDFLAGS :=

LOCAL_SHARED_LIBRARIES := \
    libwrs_omxil_common \
    libdrm \
    libva_videodecoder \
    liblog \
    libva \
    libva-android \
    libsepdrm

LOCAL_C_INCLUDES := \
    $(TARGET_OUT_HEADERS)/wrs_omxil_core \
    $(TARGET_OUT_HEADERS)/khronos/openmax \
    $(PV_INCLUDES) \
    $(TARGET_OUT_HEADERS)/libmix_videodecoder \
    $(TARGET_OUT_HEADERS)/libva \
    $(TARGET_OUT_HEADERS)/libsepdrm \
    $(TARGET_OUT_HEADERS)/drm \
    $(TARGET_OUT_HEADERS)/libdrm \
    $(TARGET_OUT_HEADERS)/libttm \
    $(TOP)/frameworks/native/include/media/hardware \
    $(TOP)/frameworks/native/include/media/openmax \
    $(TOP)/$(KERNEL_SRC_DIR)/drivers/staging/intel_media/common

LOCAL_SRC_FILES := \
    OMXComponentCodecBase.cpp\
    OMXVideoDecoderBase.cpp\
    OMXVideoDecoderAVCSecure.cpp

LOCAL_MODULE_TAGS := optional
LOCAL_MODULE := libOMXVideoDecoderAVCSecure
CTP_PRODUCT := \
        ctp_pr1 \
        ctp_nomodem \
        redhookbay
ifneq ($(filter $(TARGET_PRODUCT),$(CTP_PRODUCT)),)
LOCAL_CFLAGS += -DVED_TILING
endif

include $(BUILD_SHARED_LIBRARY)

# Add source codes for Merrifield
MERRIFIELD_PRODUCT := \
        mrfl_vp \
        mrfl_hvp \
        mrfl_sle \
        merr_vv
ifneq ($(filter $(TARGET_PRODUCT),$(MERRIFIELD_PRODUCT)),)
include $(CLEAR_VARS)
LOCAL_CPPFLAGS :=
LOCAL_LDFLAGS :=

LOCAL_SHARED_LIBRARIES := \
    libwrs_omxil_common \
    libva_videodecoder \
    liblog \
    libva \
    libva-android

LOCAL_C_INCLUDES := \
    $(TARGET_OUT_HEADERS)/wrs_omxil_core \
    $(TARGET_OUT_HEADERS)/khronos/openmax \
    $(PV_INCLUDES) \
    $(TARGET_OUT_HEADERS)/libmix_videodecoder \
    $(TARGET_OUT_HEADERS)/libva \
    $(TOP)/frameworks/native/include/media/hardware \
    $(TOP)/frameworks/native/include/media/openmax

LOCAL_SRC_FILES := \
    OMXComponentCodecBase.cpp\
    OMXVideoDecoderBase.cpp\
    OMXVideoDecoderVP8.cpp

LOCAL_MODULE_TAGS := optional
LOCAL_MODULE := libOMXVideoDecoderVP8
include $(BUILD_SHARED_LIBRARY)
endif

endif
