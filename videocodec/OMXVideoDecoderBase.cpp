/*
* Copyright (c) 2009-2011 Intel Corporation.  All rights reserved.
*
* Licensed under the Apache License, Version 2.0 (the "License");
* you may not use this file except in compliance with the License.
* You may obtain a copy of the License at
*
* http://www.apache.org/licenses/LICENSE-2.0
*
* Unless required by applicable law or agreed to in writing, software
* distributed under the License is distributed on an "AS IS" BASIS,
* WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
* See the License for the specific language governing permissions and
* limitations under the License.
*/

//#define LOG_NDEBUG 0
#define LOG_TAG "OMXVideoDecoder"
#include <utils/Log.h>
#include "OMXVideoDecoderBase.h"
#include <va/va_android.h>


static const char* VA_RAW_MIME_TYPE = "video/x-raw-va";
static const uint32_t VA_COLOR_FORMAT = 0x7FA00E00;

OMXVideoDecoderBase::OMXVideoDecoderBase()
    : mVideoDecoder(NULL),
      mNativeBufferCount(OUTPORT_NATIVE_BUFFER_COUNT),
      mOMXBufferHeaderTypePtrNum(0),
      mRotationDegrees(0),
      mWorkingMode(RAWDATA_MODE) {
      memset(&mGraphicBufferParam, 0, sizeof(mGraphicBufferParam));
}

OMXVideoDecoderBase::~OMXVideoDecoderBase() {
    releaseVideoDecoder(mVideoDecoder);

    if (this->ports) {
        if (this->ports[INPORT_INDEX]) {
            delete this->ports[INPORT_INDEX];
            this->ports[INPORT_INDEX] = NULL;
        }

        if (this->ports[OUTPORT_INDEX]) {
            delete this->ports[OUTPORT_INDEX];
            this->ports[OUTPORT_INDEX] = NULL;
        }
    }
}

OMX_ERRORTYPE OMXVideoDecoderBase::InitInputPort(void) {
    this->ports[INPORT_INDEX] = new PortVideo;
    if (this->ports[INPORT_INDEX] == NULL) {
        return OMX_ErrorInsufficientResources;
    }

    PortVideo *port = static_cast<PortVideo *>(this->ports[INPORT_INDEX]);

    // OMX_PARAM_PORTDEFINITIONTYPE
    OMX_PARAM_PORTDEFINITIONTYPE paramPortDefinitionInput;
    memset(&paramPortDefinitionInput, 0, sizeof(paramPortDefinitionInput));
    SetTypeHeader(&paramPortDefinitionInput, sizeof(paramPortDefinitionInput));
    paramPortDefinitionInput.nPortIndex = INPORT_INDEX;
    paramPortDefinitionInput.eDir = OMX_DirInput;
    paramPortDefinitionInput.nBufferCountActual = INPORT_ACTUAL_BUFFER_COUNT;
    paramPortDefinitionInput.nBufferCountMin = INPORT_MIN_BUFFER_COUNT;
    paramPortDefinitionInput.nBufferSize = INPORT_BUFFER_SIZE;
    paramPortDefinitionInput.bEnabled = OMX_TRUE;
    paramPortDefinitionInput.bPopulated = OMX_FALSE;
    paramPortDefinitionInput.eDomain = OMX_PortDomainVideo;
    paramPortDefinitionInput.format.video.cMIMEType = NULL; // to be overridden
    paramPortDefinitionInput.format.video.pNativeRender = NULL;
    paramPortDefinitionInput.format.video.nFrameWidth = 176;
    paramPortDefinitionInput.format.video.nFrameHeight = 144;
    paramPortDefinitionInput.format.video.nStride = 0;
    paramPortDefinitionInput.format.video.nSliceHeight = 0;
    paramPortDefinitionInput.format.video.nBitrate = 64000;
    paramPortDefinitionInput.format.video.xFramerate = 15 << 16;
    // TODO: check if we need to set bFlagErrorConcealment  to OMX_TRUE
    paramPortDefinitionInput.format.video.bFlagErrorConcealment = OMX_FALSE;
    paramPortDefinitionInput.format.video.eCompressionFormat = OMX_VIDEO_CodingUnused; // to be overridden
    paramPortDefinitionInput.format.video.eColorFormat = OMX_COLOR_FormatUnused;
    paramPortDefinitionInput.format.video.pNativeWindow = NULL;
    paramPortDefinitionInput.bBuffersContiguous = OMX_FALSE;
    paramPortDefinitionInput.nBufferAlignment = 0;

    // Derived class must implement this interface and override any field if needed.
    // eCompressionFormat and and cMIMEType must be overridden
    InitInputPortFormatSpecific(&paramPortDefinitionInput);

    port->SetPortDefinition(&paramPortDefinitionInput, true);

    // OMX_VIDEO_PARAM_PORTFORMATTYPE
    OMX_VIDEO_PARAM_PORTFORMATTYPE paramPortFormat;
    memset(&paramPortFormat, 0, sizeof(paramPortFormat));
    SetTypeHeader(&paramPortFormat, sizeof(paramPortFormat));
    paramPortFormat.nPortIndex = INPORT_INDEX;
    paramPortFormat.nIndex = 0;
    paramPortFormat.eCompressionFormat = paramPortDefinitionInput.format.video.eCompressionFormat;
    paramPortFormat.eColorFormat = paramPortDefinitionInput.format.video.eColorFormat;
    paramPortFormat.xFramerate = paramPortDefinitionInput.format.video.xFramerate;

    port->SetPortVideoParam(&paramPortFormat, true);

    return OMX_ErrorNone;
}


OMX_ERRORTYPE OMXVideoDecoderBase::InitOutputPort(void) {
    this->ports[OUTPORT_INDEX] = new PortVideo;
    if (this->ports[OUTPORT_INDEX] == NULL) {
        return OMX_ErrorInsufficientResources;
    }

    PortVideo *port = static_cast<PortVideo *>(this->ports[OUTPORT_INDEX]);

    // OMX_PARAM_PORTDEFINITIONTYPE
    OMX_PARAM_PORTDEFINITIONTYPE paramPortDefinitionOutput;

    memset(&paramPortDefinitionOutput, 0, sizeof(paramPortDefinitionOutput));
    SetTypeHeader(&paramPortDefinitionOutput, sizeof(paramPortDefinitionOutput));

    paramPortDefinitionOutput.nPortIndex = OUTPORT_INDEX;
    paramPortDefinitionOutput.eDir = OMX_DirOutput;
    paramPortDefinitionOutput.nBufferCountActual = OUTPORT_ACTUAL_BUFFER_COUNT;
    paramPortDefinitionOutput.nBufferCountMin = OUTPORT_MIN_BUFFER_COUNT;
    paramPortDefinitionOutput.nBufferSize = sizeof(VideoRenderBuffer);

    paramPortDefinitionOutput.bEnabled = OMX_TRUE;
    paramPortDefinitionOutput.bPopulated = OMX_FALSE;
    paramPortDefinitionOutput.eDomain = OMX_PortDomainVideo;
    paramPortDefinitionOutput.format.video.cMIMEType = (OMX_STRING)VA_RAW_MIME_TYPE;
    paramPortDefinitionOutput.format.video.pNativeRender = NULL;
    paramPortDefinitionOutput.format.video.nFrameWidth = 176;
    paramPortDefinitionOutput.format.video.nFrameHeight = 144;
    paramPortDefinitionOutput.format.video.nStride = 176;
    paramPortDefinitionOutput.format.video.nSliceHeight = 144;
    paramPortDefinitionOutput.format.video.nBitrate = 64000;
    paramPortDefinitionOutput.format.video.xFramerate = 15 << 16;
    paramPortDefinitionOutput.format.video.bFlagErrorConcealment = OMX_FALSE;
    paramPortDefinitionOutput.format.video.eCompressionFormat = OMX_VIDEO_CodingUnused;
    paramPortDefinitionOutput.format.video.eColorFormat = OMX_COLOR_FormatYUV420SemiPlanar;
    paramPortDefinitionOutput.format.video.pNativeWindow = NULL;
    paramPortDefinitionOutput.bBuffersContiguous = OMX_FALSE;
    paramPortDefinitionOutput.nBufferAlignment = 0;

    // no format specific to initialize output port
    InitOutputPortFormatSpecific(&paramPortDefinitionOutput);

    port->SetPortDefinition(&paramPortDefinitionOutput, true);

    // OMX_VIDEO_PARAM_PORTFORMATTYPE
    OMX_VIDEO_PARAM_PORTFORMATTYPE paramPortFormat;
    SetTypeHeader(&paramPortFormat, sizeof(paramPortFormat));
    paramPortFormat.nPortIndex = OUTPORT_INDEX;
    paramPortFormat.nIndex = 0;
    paramPortFormat.eCompressionFormat = paramPortDefinitionOutput.format.video.eCompressionFormat;
    paramPortFormat.eColorFormat = paramPortDefinitionOutput.format.video.eColorFormat;
    paramPortFormat.xFramerate = paramPortDefinitionOutput.format.video.xFramerate;

    port->SetPortVideoParam(&paramPortFormat, true);

    return OMX_ErrorNone;
}

OMX_ERRORTYPE OMXVideoDecoderBase::InitOutputPortFormatSpecific(OMX_PARAM_PORTDEFINITIONTYPE *paramPortDefinitionOutput) {
    // no format specific to initialize output port
    return OMX_ErrorNone;
}

OMX_ERRORTYPE OMXVideoDecoderBase::ProcessorInit(void) {
    OMX_ERRORTYPE ret;
    ret = OMXComponentCodecBase::ProcessorInit();
    CHECK_RETURN_VALUE("OMXComponentCodecBase::ProcessorInit");

    if (mVideoDecoder == NULL) {
        LOGE("ProcessorInit: Video decoder is not created.");
        return OMX_ErrorDynamicResourcesUnavailable;
    }

    VideoConfigBuffer configBuffer;
    ret = PrepareConfigBuffer(&configBuffer);
    CHECK_RETURN_VALUE("PrepareConfigBuffer");

    //pthread_mutex_lock(&mSerializationLock);
    Decode_Status status = mVideoDecoder->start(&configBuffer);
    //pthread_mutex_unlock(&mSerializationLock);

    if (status != DECODE_SUCCESS) {
        return TranslateDecodeStatus(status);
    }

    return OMX_ErrorNone;
}

OMX_ERRORTYPE OMXVideoDecoderBase::ProcessorReset(void) {
    OMX_ERRORTYPE ret;
    VideoConfigBuffer configBuffer;
    // reset the configbuffer and set it to mix
    ret = PrepareConfigBuffer(&configBuffer);
    CHECK_RETURN_VALUE("PrepareConfigBuffer");
    mVideoDecoder->reset(&configBuffer);
    return OMX_ErrorNone;
}


OMX_ERRORTYPE OMXVideoDecoderBase::ProcessorDeinit(void) {
    if (mWorkingMode != GRAPHICBUFFER_MODE) {
        if (mVideoDecoder == NULL) {
            LOGE("ProcessorDeinit: Video decoder is not created.");
            return OMX_ErrorDynamicResourcesUnavailable;
        }
        mVideoDecoder->stop();
    }
    mOMXBufferHeaderTypePtrNum = 0;
    memset(&mGraphicBufferParam, 0, sizeof(mGraphicBufferParam));
    mRotationDegrees = 0;
    return OMXComponentCodecBase::ProcessorDeinit();
}

OMX_ERRORTYPE OMXVideoDecoderBase::ProcessorStart(void) {
    return OMXComponentCodecBase::ProcessorStart();
}

OMX_ERRORTYPE OMXVideoDecoderBase::ProcessorStop(void) {
    // There is no need to return all retained buffers as we don't accumulate buffer
    //this->ports[INPORT_INDEX]->ReturnAllRetainedBuffers();

    // TODO: this is new code
    ProcessorFlush(OMX_ALL);
    if (mWorkingMode == GRAPHICBUFFER_MODE) {
        // for GRAPHICBUFFER_MODE mode, va_destroySurface need to lock the graphicbuffer,
        // Make sure va_destroySurface is called(ExecutingToIdle) before graphicbuffer is freed(IdleToLoaded).
        if (mVideoDecoder == NULL) {
            LOGE("ProcessorStop: Video decoder is not created.");
            return OMX_ErrorDynamicResourcesUnavailable;
        }
        mVideoDecoder->stop();
    }
    return OMXComponentCodecBase::ProcessorStop();
}

OMX_ERRORTYPE OMXVideoDecoderBase::ProcessorPause(void) {
    return OMXComponentCodecBase::ProcessorPause();
}

OMX_ERRORTYPE OMXVideoDecoderBase::ProcessorResume(void) {
    return OMXComponentCodecBase::ProcessorResume();
}

OMX_ERRORTYPE OMXVideoDecoderBase::ProcessorFlush(OMX_U32 portIndex) {
    LOGI("Flushing port# %lu.", portIndex);
    if (mVideoDecoder == NULL) {
        LOGE("ProcessorFlush: Video decoder is not created.");
        return OMX_ErrorDynamicResourcesUnavailable;
    }

    // Portbase has returned all retained buffers.
    if (portIndex == INPORT_INDEX || portIndex == OMX_ALL) {
        //pthread_mutex_lock(&mSerializationLock);
        LOGW("Flushing video pipeline.");
        mVideoDecoder->flush();
        //pthread_mutex_unlock(&mSerializationLock);
    }
    // TODO: do we need to flush output port?
    return OMX_ErrorNone;
}

OMX_ERRORTYPE OMXVideoDecoderBase::ProcessorPreFreeBuffer(OMX_U32 nPortIndex, OMX_BUFFERHEADERTYPE * pBuffer) {
    if (mWorkingMode == GRAPHICBUFFER_MODE)
        return OMX_ErrorNone;

    if (nPortIndex == OUTPORT_INDEX && pBuffer->pPlatformPrivate) {
        VideoRenderBuffer *p = (VideoRenderBuffer *)pBuffer->pPlatformPrivate;
        p->renderDone = true;
        pBuffer->pPlatformPrivate = NULL;
    }
    return OMX_ErrorNone;
}

 OMX_ERRORTYPE OMXVideoDecoderBase::ProcessorPreFillBuffer(OMX_BUFFERHEADERTYPE* buffer) {

    if (mWorkingMode == GRAPHICBUFFER_MODE && buffer->nOutputPortIndex == OUTPORT_INDEX){
        Decode_Status status;
        if(mVideoDecoder == NULL){
            LOGW("ProcessorPreFillBuffer: Video decoder is not created");
            return OMX_ErrorDynamicResourcesUnavailable;
        }
        status = mVideoDecoder->signalRenderDone(buffer->pBuffer);

        if (status != DECODE_SUCCESS) {
            LOGW("ProcessorPreFillBuffer:: signalRenderDone return error");
            return TranslateDecodeStatus(status);
        }
    } else if (buffer->pPlatformPrivate && buffer->nOutputPortIndex == OUTPORT_INDEX){
        VideoRenderBuffer *p = (VideoRenderBuffer *)buffer->pPlatformPrivate;
        p->renderDone = true;
        buffer->pPlatformPrivate = NULL;
    }
    return OMX_ErrorNone;
}

OMX_ERRORTYPE OMXVideoDecoderBase::ProcessorProcess(
    OMX_BUFFERHEADERTYPE ***pBuffers,
    buffer_retain_t *retains,
    OMX_U32 numberBuffers) {

    OMX_ERRORTYPE ret;
    Decode_Status status;
    // fill render buffer without draining decoder output queue
    ret = FillRenderBuffer(pBuffers[OUTPORT_INDEX], &retains[OUTPORT_INDEX], 0);
    if (ret == OMX_ErrorNone) {
        retains[INPORT_INDEX] = BUFFER_RETAIN_GETAGAIN;
        // TODO: continue decoding
        return ret;
    } else if (ret != OMX_ErrorNotReady) {
        return ret;
    }

    VideoDecodeBuffer decodeBuffer;
    // PrepareDecodeBuffer will set retain to either BUFFER_RETAIN_GETAGAIN or BUFFER_RETAIN_NOT_RETAIN
    ret = PrepareDecodeBuffer(*pBuffers[INPORT_INDEX], &retains[INPORT_INDEX], &decodeBuffer);
    if (ret == OMX_ErrorNotReady) {
        retains[OUTPORT_INDEX] = BUFFER_RETAIN_GETAGAIN;
        return OMX_ErrorNone;
    } else if (ret != OMX_ErrorNone) {
        return ret;
    }

    if (decodeBuffer.size != 0) {
        //pthread_mutex_lock(&mSerializationLock);
        status = mVideoDecoder->decode(&decodeBuffer);
        //pthread_mutex_unlock(&mSerializationLock);

        if (status == DECODE_FORMAT_CHANGE) {
            ret = HandleFormatChange();
            CHECK_RETURN_VALUE("HandleFormatChange");
            ((*pBuffers[OUTPORT_INDEX]))->nFilledLen = 0;
            retains[OUTPORT_INDEX] = BUFFER_RETAIN_GETAGAIN;
            retains[INPORT_INDEX] = BUFFER_RETAIN_GETAGAIN;
            // real dynamic resolution change will be handled later
            // Here is just a temporary workaround
            // don't use the output buffer if format is changed.
            return OMX_ErrorNone;
        } else if (status == DECODE_NO_CONFIG) {
            LOGW("Decoder returns DECODE_NO_CONFIG.");
            retains[OUTPORT_INDEX] = BUFFER_RETAIN_GETAGAIN;
            return OMX_ErrorNone;
        } else if (status == DECODE_NO_REFERENCE) {
            LOGW("Decoder returns DECODE_NO_REFERENCE.");
            //retains[OUTPORT_INDEX] = BUFFER_RETAIN_GETAGAIN;
            //return OMX_ErrorNone;
        } else if (status == DECODE_MULTIPLE_FRAME){
            if (decodeBuffer.ext != NULL && decodeBuffer.ext->extType == PACKED_FRAME_TYPE && decodeBuffer.ext->extData != NULL) {
                PackedFrameData* nextFrame = (PackedFrameData*)decodeBuffer.ext->extData;
                (*pBuffers[INPORT_INDEX])->nOffset += nextFrame->offSet;
                (*pBuffers[INPORT_INDEX])->nTimeStamp = nextFrame->timestamp;
                (*pBuffers[INPORT_INDEX])->nFilledLen -= nextFrame->offSet;
                retains[INPORT_INDEX] = BUFFER_RETAIN_GETAGAIN;
                LOGW("Find multiple frames in a buffer, next frame offset = %d, timestamp = %lld", (*pBuffers[INPORT_INDEX])->nOffset, (*pBuffers[INPORT_INDEX])->nTimeStamp);
            }
        }
        else if (status != DECODE_SUCCESS && status != DECODE_FRAME_DROPPED) {
            if (checkFatalDecoderError(status)) {
                return TranslateDecodeStatus(status);
            } else {
                // For decoder errors that could be omitted,  not throw error and continue to decode.
                TranslateDecodeStatus(status);

                ((*pBuffers[OUTPORT_INDEX]))->nFilledLen = 0;

                // Do not return, and try to drain the output queue
                // retains[OUTPORT_INDEX] = BUFFER_RETAIN_GETAGAIN;
                // return OMX_ErrorNone;
            }
        }
    }
    // drain the decoder output queue when in EOS state and fill the render buffer
    ret = FillRenderBuffer(pBuffers[OUTPORT_INDEX], &retains[OUTPORT_INDEX], ((*pBuffers[INPORT_INDEX]))->nFlags);

    bool inputEoS = ((*pBuffers[INPORT_INDEX])->nFlags & OMX_BUFFERFLAG_EOS);
    bool outputEoS = ((*pBuffers[OUTPORT_INDEX])->nFlags & OMX_BUFFERFLAG_EOS);
    // if output port is not eos, retain the input buffer until all the output buffers are drained.
    if (inputEoS && !outputEoS) {
        retains[INPORT_INDEX] = BUFFER_RETAIN_GETAGAIN;
        // the input buffer is retained for draining purpose. Set nFilledLen to 0 so buffer will not be decoded again.
        (*pBuffers[INPORT_INDEX])->nFilledLen = 0;
    }

    if (ret == OMX_ErrorNotReady) {
        retains[OUTPORT_INDEX] = BUFFER_RETAIN_GETAGAIN;
        ret = OMX_ErrorNone;
    }

    return ret;
}

bool OMXVideoDecoderBase::IsAllBufferAvailable(void) {
    bool b = ComponentBase::IsAllBufferAvailable();
    if (b == false) {
        return false;
    }

    PortVideo *port = NULL;
    port = static_cast<PortVideo *>(this->ports[OUTPORT_INDEX]);
    const OMX_PARAM_PORTDEFINITIONTYPE* port_def = port->GetPortDefinition();
     // if output port is disabled, retain the input buffer
    if (!port_def->bEnabled) {
        return false;
    }

    if (mVideoDecoder) {
        return mVideoDecoder->checkBufferAvail();
    }
    return false;
}

OMX_ERRORTYPE OMXVideoDecoderBase::PrepareConfigBuffer(VideoConfigBuffer *p) {
    // default config buffer preparation
    memset(p, 0, sizeof(VideoConfigBuffer));

    const OMX_PARAM_PORTDEFINITIONTYPE *paramPortDefinitionInput = this->ports[INPORT_INDEX]->GetPortDefinition();
    if (paramPortDefinitionInput == NULL) {
        return OMX_ErrorBadParameter;
    }

    if (mWorkingMode == GRAPHICBUFFER_MODE) {
        p->surfaceNumber = mOMXBufferHeaderTypePtrNum;
        for (int i = 0; i < mOMXBufferHeaderTypePtrNum; i++){
            OMX_BUFFERHEADERTYPE *buffer_hdr = mOMXBufferHeaderTypePtrArray[i];
            p->graphicBufferHandler[i] = buffer_hdr->pBuffer;
            LOGV("PrepareConfigBuffer bufferid = %p, handle = %p", buffer_hdr, buffer_hdr->pBuffer);
        }
        p->flag |= USE_NATIVE_GRAPHIC_BUFFER;
        p->graphicBufferStride = mGraphicBufferParam.graphicBufferStride;
        p->graphicBufferColorFormat = mGraphicBufferParam.graphicBufferColorFormat;
        p->graphicBufferWidth = mGraphicBufferParam.graphicBufferWidth;
        p->graphicBufferHeight = mGraphicBufferParam.graphicBufferHeight;

        PortVideo *port = NULL;
        port = static_cast<PortVideo *>(this->ports[INPORT_INDEX]);
        OMX_PARAM_PORTDEFINITIONTYPE port_def;
        memcpy(&port_def, port->GetPortDefinition(), sizeof(port_def));

        if (port_def.format.video.pNativeWindow != NULL) {
            p->nativeWindow = port_def.format.video.pNativeWindow;
            LOGD("NativeWindow = %p", p->nativeWindow);
        }

    }
    p->rotationDegrees = mRotationDegrees;
    p->width = paramPortDefinitionInput->format.video.nFrameWidth;
    p->height = paramPortDefinitionInput->format.video.nFrameHeight;
    return OMX_ErrorNone;
}

OMX_ERRORTYPE OMXVideoDecoderBase::PrepareDecodeBuffer(OMX_BUFFERHEADERTYPE *buffer, buffer_retain_t *retain, VideoDecodeBuffer *p) {
    // default decode buffer preparation
    memset(p, 0, sizeof(VideoDecodeBuffer));
    if (buffer->nFilledLen == 0) {
        LOGW("Len of filled data to decode is 0.");
        return OMX_ErrorNone; //OMX_ErrorBadParameter;
    }

    if (buffer->pBuffer == NULL) {
        LOGE("Buffer to decode is empty.");
        return OMX_ErrorBadParameter;
    }

    if (buffer->nFlags & OMX_BUFFERFLAG_CODECCONFIG) {
        LOGI("Buffer has OMX_BUFFERFLAG_CODECCONFIG flag.");
    }

    if (buffer->nFlags & OMX_BUFFERFLAG_DECODEONLY) {
        // TODO: Handle OMX_BUFFERFLAG_DECODEONLY : drop the decoded frame without rendering it.
        LOGW("Buffer has OMX_BUFFERFLAG_DECODEONLY flag.");
    }

    p->data = buffer->pBuffer + buffer->nOffset;
    p->size = buffer->nFilledLen;
    p->timeStamp = buffer->nTimeStamp;
    if (buffer->nFlags & (OMX_BUFFERFLAG_ENDOFFRAME | OMX_BUFFERFLAG_EOS)) {
        // TODO: OMX_BUFFERFLAG_ENDOFFRAME can be used to indicate end of a NAL unit.
        // setting this flag may cause corruption if buffer does not contain end-of-frame data.
        p->flag = HAS_COMPLETE_FRAME;
    }

    if (buffer->nFlags & OMX_BUFFERFLAG_SYNCFRAME) {
        p->flag |= IS_SYNC_FRAME;
    }

    *retain= BUFFER_RETAIN_NOT_RETAIN;
    return OMX_ErrorNone;
}

OMX_ERRORTYPE OMXVideoDecoderBase::FillRenderBuffer(OMX_BUFFERHEADERTYPE **pBuffer, buffer_retain_t *retain, OMX_U32 inportBufferFlags) {

    OMX_BUFFERHEADERTYPE *buffer = *pBuffer;
    OMX_BUFFERHEADERTYPE *buffer_orign = buffer;

    if (mWorkingMode != GRAPHICBUFFER_MODE && buffer->pPlatformPrivate) {
        VideoRenderBuffer *p = (VideoRenderBuffer *)buffer->pPlatformPrivate;
        p->renderDone = true;
        buffer->pPlatformPrivate = NULL;
    }

    bool draining = (inportBufferFlags & OMX_BUFFERFLAG_EOS);
    //pthread_mutex_lock(&mSerializationLock);
    const VideoRenderBuffer *renderBuffer = mVideoDecoder->getOutput(draining);
    //pthread_mutex_unlock(&mSerializationLock);
    if (renderBuffer == NULL) {
        buffer->nFilledLen = 0;
        if (draining) {
            LOGI("output EOS received");
            buffer->nFlags = OMX_BUFFERFLAG_EOS;
            return OMX_ErrorNone;
        }
        return OMX_ErrorNotReady;
    }

    if (mWorkingMode == GRAPHICBUFFER_MODE) {
        buffer = *pBuffer = mOMXBufferHeaderTypePtrArray[renderBuffer->graphicBufferIndex];
     }

    buffer->nFlags = OMX_BUFFERFLAG_ENDOFFRAME;
#ifdef DEINTERLACE_EXT
    if (renderBuffer->scanFormat & (VA_TOP_FIELD | VA_BOTTOM_FIELD))
        buffer->nFlags |= OMX_BUFFERFLAG_TFF;
#endif
    buffer->nTimeStamp = renderBuffer->timeStamp;

    if (renderBuffer->flag & IS_EOS) {
        buffer->nFlags |= OMX_BUFFERFLAG_EOS;
    }

    if (mWorkingMode == GRAPHICBUFFER_MODE) {
        if (buffer_orign != buffer) {
            *retain = BUFFER_RETAIN_OVERRIDDEN;
        }
         buffer->nFilledLen = sizeof(OMX_U8*);
    } else {
        OMX_ERRORTYPE  ret = MapRawNV12(renderBuffer, buffer->pBuffer + buffer->nOffset, buffer->nFilledLen);
        CHECK_RETURN_VALUE("MapRawNV12");
        buffer->pPlatformPrivate = (void *)renderBuffer;
    }

    return OMX_ErrorNone;
}

OMX_ERRORTYPE OMXVideoDecoderBase::HandleFormatChange(void) {
    LOGW("Video format is changed.");
    //pthread_mutex_lock(&mSerializationLock);
    const VideoFormatInfo *formatInfo = mVideoDecoder->getFormatInfo();
    //pthread_mutex_unlock(&mSerializationLock);

    // Sync port definition as it may change.
    OMX_PARAM_PORTDEFINITIONTYPE paramPortDefinitionInput, paramPortDefinitionOutput;

    memcpy(&paramPortDefinitionInput,
        this->ports[INPORT_INDEX]->GetPortDefinition(),
        sizeof(paramPortDefinitionInput));

    memcpy(&paramPortDefinitionOutput,
        this->ports[OUTPORT_INDEX]->GetPortDefinition(),
        sizeof(paramPortDefinitionOutput));

    int width = formatInfo->width;
    int height = formatInfo->height;
    int stride = formatInfo->width;
    int sliceHeight = formatInfo->height;

    int widthCropped = formatInfo->width - formatInfo->cropLeft - formatInfo->cropRight;
    int heightCropped = formatInfo->height - formatInfo->cropTop - formatInfo->cropBottom;
    int strideCropped = widthCropped;
    int sliceHeightCropped = heightCropped;
    int force_realloc = 0;

    if (paramPortDefinitionOutput.nBufferCountActual < formatInfo->actualBufferNeeded) {
        if (mWorkingMode == GRAPHICBUFFER_MODE) {
            LOGV("output port buffer number is not enough: %d to %d",
                 paramPortDefinitionOutput.nBufferCountActual,
                 formatInfo->actualBufferNeeded);
            paramPortDefinitionOutput.nBufferCountActual = mNativeBufferCount = formatInfo->actualBufferNeeded;
            force_realloc = 1;
        }
    }

    LOGV("Original size = %lu x %lu, new size = %d x %d, cropped size = %d x %d",
        paramPortDefinitionInput.format.video.nFrameWidth,
        paramPortDefinitionInput.format.video.nFrameHeight,
        width, height, widthCropped, heightCropped);

    if (!force_realloc &&
        widthCropped == paramPortDefinitionOutput.format.video.nFrameWidth &&
        heightCropped == paramPortDefinitionOutput.format.video.nFrameHeight) {
        if (mWorkingMode == RAWDATA_MODE) {
            LOGW("Change of portsetting is not reported as size is not changed.");
            return OMX_ErrorNone;
        }
    }

    paramPortDefinitionInput.format.video.nFrameWidth = width;
    paramPortDefinitionInput.format.video.nFrameHeight = height;
    paramPortDefinitionInput.format.video.nStride = stride;
    paramPortDefinitionInput.format.video.nSliceHeight = sliceHeight;

    if (mWorkingMode == RAWDATA_MODE) {
        paramPortDefinitionOutput.format.video.nFrameWidth = widthCropped;
        paramPortDefinitionOutput.format.video.nFrameHeight = heightCropped;
        paramPortDefinitionOutput.format.video.nStride = strideCropped;
        paramPortDefinitionOutput.format.video.nSliceHeight = sliceHeightCropped;
    } else if (mWorkingMode == GRAPHICBUFFER_MODE) {
        // when the width and height ES parse are not larger than allocated graphic buffer in outport,
        // there is no need to reallocate graphic buffer,just report the crop info to omx client
        if (!force_realloc && width <= formatInfo->surfaceWidth && height <= formatInfo->surfaceHeight) {
            this->ports[INPORT_INDEX]->SetPortDefinition(&paramPortDefinitionInput, true);
            this->ports[OUTPORT_INDEX]->ReportOutputCrop();
            return OMX_ErrorNone;
        }

        if (width > formatInfo->surfaceWidth ||  height > formatInfo->surfaceHeight) {
            // update the real decoded resolution to outport instead of display resolution for graphic buffer reallocation
            // when the width and height parsed from ES are larger than allocated graphic buffer in outport,
            paramPortDefinitionOutput.format.video.nFrameWidth = width;
#ifdef VED_TILING
            if (width > 1280) {
               LOGI("HD Video and use tiled format");
               paramPortDefinitionOutput.format.video.eColorFormat = OMX_INTEL_COLOR_FormatYUV420PackedSemiPlanar_Tiled;
            } else {
               paramPortDefinitionOutput.format.video.eColorFormat = OMX_INTEL_COLOR_FormatYUV420PackedSemiPlanar;
            }
#endif
            paramPortDefinitionOutput.format.video.nFrameHeight = (height + 0x1f) & ~0x1f;
            paramPortDefinitionOutput.format.video.nStride = stride;
            paramPortDefinitionOutput.format.video.nSliceHeight = sliceHeight;
       }
    }

    paramPortDefinitionOutput.bEnabled = (OMX_BOOL)false;
    mOMXBufferHeaderTypePtrNum = 0;
    memset(&mGraphicBufferParam, 0, sizeof(mGraphicBufferParam));

    this->ports[INPORT_INDEX]->SetPortDefinition(&paramPortDefinitionInput, true);
    this->ports[OUTPORT_INDEX]->SetPortDefinition(&paramPortDefinitionOutput, true);

    this->ports[OUTPORT_INDEX]->ReportPortSettingsChanged();
    return OMX_ErrorNone;
}

OMX_ERRORTYPE OMXVideoDecoderBase::TranslateDecodeStatus(Decode_Status status) {
    switch (status) {
        case DECODE_NEED_RESTART:
            LOGE("Decoder returned DECODE_NEED_RESTART");
            return (OMX_ERRORTYPE)OMX_ErrorIntelVideoNotPermitted;
        case DECODE_NO_CONFIG:
            LOGE("Decoder returned DECODE_NO_CONFIG");
            return (OMX_ERRORTYPE)OMX_ErrorIntelMissingConfig;
        case DECODE_NO_SURFACE:
            LOGE("Decoder returned DECODE_NO_SURFACE");
            return OMX_ErrorDynamicResourcesUnavailable;
        case DECODE_NO_REFERENCE:
            LOGE("Decoder returned DECODE_NO_REFERENCE");
            return OMX_ErrorDynamicResourcesUnavailable; // TO DO
        case DECODE_NO_PARSER:
            LOGE("Decoder returned DECODE_NO_PARSER");
            return OMX_ErrorDynamicResourcesUnavailable;
        case DECODE_INVALID_DATA:
            LOGE("Decoder returned DECODE_INVALID_DATA");
            return OMX_ErrorBadParameter;
        case DECODE_DRIVER_FAIL:
            LOGE("Decoder returned DECODE_DRIVER_FAIL");
            return OMX_ErrorHardware;
        case DECODE_PARSER_FAIL:
            LOGE("Decoder returned DECODE_PARSER_FAIL");
            return (OMX_ERRORTYPE)OMX_ErrorIntelProcessStream; // OMX_ErrorStreamCorrupt
        case DECODE_MEMORY_FAIL:
            LOGE("Decoder returned DECODE_MEMORY_FAIL");
            return OMX_ErrorInsufficientResources;
        case DECODE_FAIL:
            LOGE("Decoder returned DECODE_FAIL");
            return OMX_ErrorUndefined;
        case DECODE_SUCCESS:
            return OMX_ErrorNone;
        case DECODE_FORMAT_CHANGE:
            LOGW("Decoder returned DECODE_FORMAT_CHANGE");
            return OMX_ErrorNone;
        case DECODE_FRAME_DROPPED:
            LOGI("Decoder returned DECODE_FRAME_DROPPED");
            return OMX_ErrorNone;
        default:
            LOGW("Decoder returned unknown error");
            return OMX_ErrorUndefined;
    }
}

OMX_ERRORTYPE OMXVideoDecoderBase::BuildHandlerList(void) {
    OMXComponentCodecBase::BuildHandlerList();
    AddHandler(OMX_IndexParamVideoPortFormat, GetParamVideoPortFormat, SetParamVideoPortFormat);
    AddHandler(static_cast<OMX_INDEXTYPE>(OMX_IndexExtGetNativeBufferUsage), GetNativeBufferUsage, SetNativeBufferUsage);
    AddHandler(static_cast<OMX_INDEXTYPE>(OMX_IndexExtUseNativeBuffer), GetNativeBuffer, SetNativeBuffer);
    AddHandler(static_cast<OMX_INDEXTYPE>(OMX_IndexExtEnableNativeBuffer), GetNativeBufferMode, SetNativeBufferMode);
    AddHandler(static_cast<OMX_INDEXTYPE>(OMX_IndexExtRotationDegrees), GetDecoderRotation, SetDecoderRotation);
    AddHandler(OMX_IndexConfigCommonOutputCrop, GetDecoderOutputCrop, SetDecoderOutputCrop);

    return OMX_ErrorNone;
}

OMX_ERRORTYPE OMXVideoDecoderBase::GetParamVideoPortFormat(OMX_PTR pStructure) {
    OMX_ERRORTYPE ret;
    OMX_VIDEO_PARAM_PORTFORMATTYPE *p = (OMX_VIDEO_PARAM_PORTFORMATTYPE *)pStructure;

    CHECK_TYPE_HEADER(p);
    CHECK_PORT_INDEX_RANGE(p);
    CHECK_ENUMERATION_RANGE(p->nIndex, 1);

    PortVideo *port = NULL;
    port = static_cast<PortVideo *>(this->ports[p->nPortIndex]);
    memcpy(p, port->GetPortVideoParam(), sizeof(*p));
    return OMX_ErrorNone;
}

OMX_ERRORTYPE OMXVideoDecoderBase::SetParamVideoPortFormat(OMX_PTR pStructure) {
    OMX_ERRORTYPE ret;
    OMX_VIDEO_PARAM_PORTFORMATTYPE *p = (OMX_VIDEO_PARAM_PORTFORMATTYPE *)pStructure;

    CHECK_TYPE_HEADER(p);
    CHECK_PORT_INDEX_RANGE(p);
    CHECK_SET_PARAM_STATE();

    // TODO: do we need to check if port is enabled?
    PortVideo *port = NULL;
    port = static_cast<PortVideo *>(this->ports[p->nPortIndex]);
    port->SetPortVideoParam(p, false);
    return OMX_ErrorNone;
}

OMX_ERRORTYPE OMXVideoDecoderBase::GetNativeBufferUsage(OMX_PTR pStructure) {
     OMX_ERRORTYPE ret;
     GetAndroidNativeBufferUsageParams *param = (GetAndroidNativeBufferUsageParams*)pStructure;
     CHECK_TYPE_HEADER(param);
     param->nUsage |= GRALLOC_USAGE_HW_TEXTURE;
     return OMX_ErrorNone;
}
OMX_ERRORTYPE OMXVideoDecoderBase::SetNativeBufferUsage(OMX_PTR pStructure) {
    CHECK_SET_PARAM_STATE();
    return OMX_ErrorBadParameter;
}

OMX_ERRORTYPE OMXVideoDecoderBase::GetNativeBuffer(OMX_PTR pStructure) {
    return OMX_ErrorBadParameter;
}
OMX_ERRORTYPE OMXVideoDecoderBase::SetNativeBuffer(OMX_PTR pStructure) {
    OMX_ERRORTYPE ret;
    UseAndroidNativeBufferParams *param = (UseAndroidNativeBufferParams*)pStructure;
    CHECK_TYPE_HEADER(param);
    if (param->nPortIndex != OUTPORT_INDEX)
        return OMX_ErrorBadParameter;
    OMX_BUFFERHEADERTYPE **buf_hdr = NULL;

    mOMXBufferHeaderTypePtrNum++;
    if (mOMXBufferHeaderTypePtrNum > MAX_GRAPHIC_BUFFER_NUM)
        return OMX_ErrorOverflow;

    buf_hdr = &mOMXBufferHeaderTypePtrArray[mOMXBufferHeaderTypePtrNum-1];

    ret = this->ports[OUTPORT_INDEX]->UseBuffer(buf_hdr, OUTPORT_INDEX, param->pAppPrivate, sizeof(OMX_U8*),
                                      const_cast<OMX_U8*>(reinterpret_cast<const OMX_U8*>(param->nativeBuffer->handle)));
    if (ret != OMX_ErrorNone)
        return ret;

    if (mOMXBufferHeaderTypePtrNum == 1) {
         mGraphicBufferParam.graphicBufferColorFormat = param->nativeBuffer->format;
         mGraphicBufferParam.graphicBufferStride = param->nativeBuffer->stride;
         mGraphicBufferParam.graphicBufferWidth = param->nativeBuffer->width;
         mGraphicBufferParam.graphicBufferHeight = param->nativeBuffer->height;
    }

    *(param->bufferHeader) = *buf_hdr;

    return OMX_ErrorNone;
}

OMX_ERRORTYPE OMXVideoDecoderBase::GetNativeBufferMode(OMX_PTR pStructure) {
    LOGE("GetNativeBufferMode is not implemented");
    return OMX_ErrorNotImplemented;
}

OMX_ERRORTYPE OMXVideoDecoderBase::SetNativeBufferMode(OMX_PTR pStructure) {
     OMX_ERRORTYPE ret;
     EnableAndroidNativeBuffersParams *param = (EnableAndroidNativeBuffersParams*)pStructure;

     CHECK_TYPE_HEADER(param);
     CHECK_PORT_INDEX_RANGE(param);
     CHECK_SET_PARAM_STATE();

     if (!param->enable) {
        mWorkingMode = RAWDATA_MODE;
        return OMX_ErrorNone;
     }
     mWorkingMode = GRAPHICBUFFER_MODE;
     PortVideo *port = NULL;
     port = static_cast<PortVideo *>(this->ports[OUTPORT_INDEX]);

     OMX_PARAM_PORTDEFINITIONTYPE port_def;
     memcpy(&port_def,port->GetPortDefinition(),sizeof(port_def));
     port_def.nBufferCountMin = 1;
     port_def.nBufferCountActual = mNativeBufferCount;
     port_def.format.video.cMIMEType = (OMX_STRING)VA_VED_RAW_MIME_TYPE;
     port_def.format.video.eColorFormat = OMX_INTEL_COLOR_FormatYUV420PackedSemiPlanar;
     port_def.format.video.nFrameHeight = (port_def.format.video.nFrameHeight + 0x1f) & ~0x1f;
#ifdef VED_TILING
     if (port_def.format.video.nFrameWidth > 1280) {
        LOGI("HD Video and use tiled format");
        port_def.format.video.eColorFormat = OMX_INTEL_COLOR_FormatYUV420PackedSemiPlanar_Tiled;
     }
#endif
     port->SetPortDefinition(&port_def,true);

     return OMX_ErrorNone;
}

OMX_ERRORTYPE OMXVideoDecoderBase::GetDecoderRotation(OMX_PTR pStructure) {
    return OMX_ErrorBadParameter;
}
OMX_ERRORTYPE OMXVideoDecoderBase::SetDecoderRotation(OMX_PTR pStructure) {
    CHECK_SET_PARAM_STATE();
    int32_t rotationDegrees = 0;

    rotationDegrees = *(static_cast<int32_t*>(pStructure));
    mRotationDegrees = rotationDegrees;

    return OMX_ErrorNone;
}

OMX_ERRORTYPE OMXVideoDecoderBase::GetDecoderOutputCrop(OMX_PTR pStructure) {
    OMX_CONFIG_RECTTYPE *rectParams = (OMX_CONFIG_RECTTYPE *)pStructure;
    if (rectParams->nPortIndex != OUTPORT_INDEX) {
        return OMX_ErrorUndefined;
    }
    const VideoFormatInfo *formatInfo = mVideoDecoder->getFormatInfo();
    if (formatInfo->valid == true) {
        rectParams->nLeft =  formatInfo->cropLeft;
        rectParams->nTop = formatInfo->cropTop;
        rectParams->nWidth = formatInfo->width - formatInfo->cropLeft - formatInfo->cropRight;
        rectParams->nHeight = formatInfo->height - formatInfo->cropTop - formatInfo->cropBottom;
        return OMX_ErrorNone;
    } else {
        return OMX_ErrorFormatNotDetected;
    }
}

OMX_ERRORTYPE OMXVideoDecoderBase::SetDecoderOutputCrop(OMX_PTR pStructure) {
    return OMX_ErrorUnsupportedSetting;
}

OMX_ERRORTYPE OMXVideoDecoderBase::MapRawNV12(const VideoRenderBuffer* renderBuffer, OMX_U8 *rawData, OMX_U32& size) {

    VAStatus vaStatus;
    VAImageFormat imageFormat;
    VAImage vaImage;
    int32_t width = this->ports[OUTPORT_INDEX]->GetPortDefinition()->format.video.nFrameWidth;
    int32_t height = this->ports[OUTPORT_INDEX]->GetPortDefinition()->format.video.nFrameHeight;

    size = width * height * 3 / 2;

    vaStatus = vaSyncSurface(renderBuffer->display, renderBuffer->surface);
    if (vaStatus != VA_STATUS_SUCCESS) {
        LOGE("vaSyncSurface failed. Error = %#x", vaStatus);
        return OMX_ErrorHardware;
    }

    vaStatus = vaDeriveImage(renderBuffer->display, renderBuffer->surface, &vaImage);
    if (vaStatus != VA_STATUS_SUCCESS) {
        LOGW("vaDeriveImage failed. Error = %#x. A faked image is returned.", vaStatus);
        int sizeY = width * height;
        memset(rawData, 16, sizeY);
        memset(rawData + sizeY, 128, sizeY/2);
        return OMX_ErrorNone;
    }

    void *pBuf = NULL;
    vaStatus = vaMapBuffer(renderBuffer->display, vaImage.buf, &pBuf);
    if (vaStatus != VA_STATUS_SUCCESS) {
        LOGE("vaMapBuffer failed. Error = %#x", vaStatus);
        return OMX_ErrorHardware;
    }

    if (size == (int32_t)vaImage.data_size) {
        memcpy(rawData, pBuf, size);
    } else {
        // copy Y data
        uint8_t *src = (uint8_t*)pBuf;
        uint8_t *dst = rawData;
        int32_t row = 0;
        for (row = height; row != 0 ; row--) {
            memcpy(dst, src, width);
            dst += width;
            src += vaImage.pitches[0];
        }
        // copy interleaved V and  U data
        src = (uint8_t*)pBuf + vaImage.offsets[1];
        for (row = height/2; row != 0 ; row--) {
            memcpy(dst, src, width);
            dst += width;
            src += vaImage.pitches[1];
        }
    }

    vaStatus = vaUnmapBuffer(renderBuffer->display, vaImage.buf);
    if (vaStatus != VA_STATUS_SUCCESS) {
        LOGW("vaUnmapBuffer failed. Error = %#x", vaStatus);
    }

    vaStatus = vaDestroyImage(renderBuffer->display, vaImage.image_id);
    if (vaStatus != VA_STATUS_SUCCESS) {
        LOGW("vaDestroyImage failed. Error = %#x", vaStatus);
    }
    return OMX_ErrorNone;
}
