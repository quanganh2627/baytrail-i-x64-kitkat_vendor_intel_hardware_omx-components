ifeq ($(strip $(BOARD_USES_WRS_OMXIL_CORE)),true)
LOCAL_PATH := $(call my-dir)


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
        libsharedbuffer

LOCAL_C_INCLUDES := \
    $(TARGET_OUT_HEADERS)/wrs_omxil_core \
    $(TARGET_OUT_HEADERS)/khronos/openmax \
    $(TARGET_OUT_HEADERS)/libmix_videoencoder \
    $(TARGET_OUT_HEADERS)/libva	\
    $(TARGET_OUT_HEADERS)/libsharedbuffer \
    $(TOP)/frameworks/native/include/media/hardware \
    $(TOP)/frameworks/native/include/media/openmax

LOCAL_SRC_FILES := \
    OMXComponentCodecBase.cpp \
    OMXVideoEncoderBase.cpp \
    OMXVideoEncoderAVC.cpp

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
        libsharedbuffer

LOCAL_C_INCLUDES := \
    $(TARGET_OUT_HEADERS)/wrs_omxil_core \
    $(TARGET_OUT_HEADERS)/khronos/openmax \
    $(TARGET_OUT_HEADERS)/libmix_videoencoder \
    $(TARGET_OUT_HEADERS)/libva	\
    $(TARGET_OUT_HEADERS)/libsharedbuffer \
    $(TOP)/frameworks/native/include/media/hardware \
    $(TOP)/frameworks/native/include/media/openmax

LOCAL_SRC_FILES := \
    OMXComponentCodecBase.cpp \
    OMXVideoEncoderBase.cpp \
    OMXVideoEncoderH263.cpp

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
        libsharedbuffer

LOCAL_C_INCLUDES := \
    $(TARGET_OUT_HEADERS)/wrs_omxil_core \
    $(TARGET_OUT_HEADERS)/khronos/openmax \
    $(TARGET_OUT_HEADERS)/libmix_videoencoder \
    $(TARGET_OUT_HEADERS)/libva	\
    $(TARGET_OUT_HEADERS)/libsharedbuffer \
    $(TOP)/frameworks/native/include/media/hardware \
    $(TOP)/frameworks/native/include/media/openmax

LOCAL_SRC_FILES := \
    OMXComponentCodecBase.cpp \
    OMXVideoEncoderBase.cpp \
    OMXVideoEncoderMPEG4.cpp

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
include $(BUILD_SHARED_LIBRARY)


include $(CLEAR_VARS)

LOCAL_CPPFLAGS :=
LOCAL_LDFLAGS :=

LOCAL_SHARED_LIBRARIES := \
    libwrs_omxil_common \
    libva_videodecoder \
    liblog \
    libva \
    libva-android \
#    libsepdrm

LOCAL_C_INCLUDES := \
    $(TARGET_OUT_HEADERS)/wrs_omxil_core \
    $(TARGET_OUT_HEADERS)/khronos/openmax \
    $(PV_INCLUDES) \
    $(TARGET_OUT_HEADERS)/libmix_videodecoder \
    $(TARGET_OUT_HEADERS)/libva \
    $(TARGET_OUT_HEADERS)/libsepdrm \
    $(TOP)/frameworks/native/include/media/hardware \
    $(TOP)/frameworks/native/include/media/openmax

LOCAL_SRC_FILES := \
    OMXComponentCodecBase.cpp\
    OMXVideoDecoderBase.cpp\
#    OMXVideoDecoderAVCSecure.cpp

LOCAL_MODULE_TAGS := optional
LOCAL_MODULE := libOMXVideoDecoderAVCSecure
include $(BUILD_SHARED_LIBRARY)




endif
