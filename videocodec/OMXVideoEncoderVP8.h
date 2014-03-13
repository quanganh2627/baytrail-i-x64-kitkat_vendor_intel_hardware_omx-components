
#ifndef OMX_VIDEO_ENCODER_VP8_H
#define OMX_VIDEO_ENCODER_VP8_H

#include "OMXVideoEncoderBase.h"

class OMXVideoEncoderVP8 : public OMXVideoEncoderBase {
    public:
        OMXVideoEncoderVP8();
        virtual ~OMXVideoEncoderVP8();
    protected:
        virtual OMX_ERRORTYPE InitOutputPortFormatSpecific(OMX_PARAM_PORTDEFINITIONTYPE *paramPortDeninitionOutput);
        virtual OMX_ERRORTYPE ProcessorInit(void);
        virtual OMX_ERRORTYPE ProcessorDeinit(void);
        virtual OMX_ERRORTYPE ProcessorProcess(OMX_BUFFERHEADERTYPE **buffers, buffer_retain_t *retains, OMX_U32 numberBuffers);
        virtual OMX_ERRORTYPE BuildHandlerList(void);
        virtual OMX_ERRORTYPE SetVideoEncoderParam();
        DECLARE_HANDLER(OMXVideoEncoderVP8, ParamVideoVp8);
        DECLARE_HANDLER(OMXVideoEncoderVP8, ConfigVideoVp8ReferenceFrame);
        DECLARE_HANDLER(OMXVideoEncoderVP8, ConfigVp8ForceKFrame);
        DECLARE_HANDLER(OMXVideoEncoderVP8, ConfigVp8MaxFrameSizeRatio);
        DECLARE_HANDLER(OMXVideoEncoderVP8, TemporalLayerNumber);
        DECLARE_HANDLER(OMXVideoEncoderVP8, ConfigTemporalLayerBitrateFramerate);
    private:
        enum {
            OUTPORT_MIN_BUFFER_COUNT = 1,
            OUTPORT_ACTUAL_BUFFER_COUNT = 2,
            OUTPORT_BUFFER_SIZE = 1382400,
        };

        OMX_VIDEO_PARAM_VP8TYPE mParamVp8;
        OMX_VIDEO_VP8REFERENCEFRAMETYPE mConfigVideoVp8ReferenceFrame;
        OMX_VIDEO_PARAM_INTEL_VP8_NUMBER_OF_TEMPORAL_LAYER mNumberOfTemporalLayer;
        OMX_VIDEO_CONFIG_INTEL_VP8_TEMPORAL_LAYER_BITRATE_FRAMERATE mTemporalLayerBitrateFramerate;
};

#endif /* OMX_VIDEO_ENCODER_VP8_H */
