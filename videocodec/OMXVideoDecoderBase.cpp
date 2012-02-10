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

#define LOG_NDEBUG 0
#define LOG_TAG "OMXVideoDecoderBase"
#include <utils/Log.h>
#include "OMXVideoDecoderBase.h"
#include <va/va_android.h>


static const char* VA_RAW_MIME_TYPE = "video/x-raw-va";
static const uint32_t VA_COLOR_FORMAT = 0x7FA00E00;

OMXVideoDecoderBase::OMXVideoDecoderBase()
    : mVideoDecoder(NULL),
      mNativeBufferMode(false),
      mOMXBufferHeaderTypePtrNum(0),
      mGraphicBuffercolorformat(0),
      mGraphicBufferStride(0){
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

OMX_ERRORTYPE OMXVideoDecoderBase::ProcessorDeinit(void) {
    if (mVideoDecoder == NULL) {
        LOGE("ProcessorDeinit: Video decoder is not created.");
        return OMX_ErrorDynamicResourcesUnavailable;
    }
    //pthread_mutex_lock(&mSerializationLock);
    mVideoDecoder->stop();
    //pthread_mutex_unlock(&mSerializationLock);

    return OMXComponentCodecBase::ProcessorDeinit();
}

OMX_ERRORTYPE OMXVideoDecoderBase::ProcessorStop(void) {
    // There is no need to return all retained buffers as we don't accumulate buffer
    //this->ports[INPORT_INDEX]->ReturnAllRetainedBuffers();

    // TODO: this is new code
    ProcessorFlush(OMX_ALL);

    return OMXComponentCodecBase::ProcessorStop();
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
        mVideoDecoder->flush();
        //pthread_mutex_unlock(&mSerializationLock);
    }
    // TODO: do we need to flush output port?
    return OMX_ErrorNone;
}

OMX_ERRORTYPE OMXVideoDecoderBase::ProcessorPreFreeBuffer(OMX_U32 nPortIndex,OMX_BUFFERHEADERTYPE * pBuffer) {
    if (mNativeBufferMode)
        return OMX_ErrorNone;

    if (nPortIndex == OUTPORT_INDEX && pBuffer->pPlatformPrivate) {
        VideoRenderBuffer *p = (VideoRenderBuffer *)pBuffer->pPlatformPrivate;
        p->renderDone = true;
        pBuffer->pPlatformPrivate = NULL;
    }
    return OMX_ErrorNone;
}

 OMX_ERRORTYPE OMXVideoDecoderBase::PreProcessBuffer(OMX_BUFFERHEADERTYPE* buffer) {

    if (mNativeBufferMode && buffer->nOutputPortIndex == OUTPORT_INDEX){
        Decode_Status status;
        if(mVideoDecoder == NULL){
            LOGE("PreProcessBuffer: Video decoder is not created");
            return OMX_ErrorDynamicResourcesUnavailable;
        }
        status = mVideoDecoder->SignalRenderDoneFlag(buffer->pBuffer);

        if (status != DECODE_SUCCESS) {
            return TranslateDecodeStatus(status);
        }
    } else if (buffer->pPlatformPrivate && buffer->nOutputPortIndex == OUTPORT_INDEX){
        VideoRenderBuffer *p = (VideoRenderBuffer *)buffer->pPlatformPrivate;
        p->renderDone = true;
        buffer->pPlatformPrivate = NULL;
    }
    return OMX_ErrorNone;
}


 OMX_ERRORTYPE OMXVideoDecoderBase::PreProcessBufferQueue_Locked(void) {
    if(!mNativeBufferMode )
       return OMX_ErrorNone;
    Decode_Status status = DECODE_SUCCESS;
    PortBase *port_out = this->ports[OUTPORT_INDEX];

    OMX_BUFFERHEADERTYPE *buffer = NULL;
    OMX_BUFFERHEADERTYPE *buffer_head = NULL;
    bool used = false;

    OMX_U32 len = port_out->BufferQueueLength();
    //check the buffer from buffer queue. used means cannot be used to decode
    for( OMX_U32 i=0; i <len; i++){
       buffer = port_out->PopBuffer();
       if(buffer == NULL)
          break;
       status = mVideoDecoder->GetNativeBufferStatus(buffer->pBuffer,&used);
       if(status != DECODE_SUCCESS){
          LOGW("GetNativeBufferStatus returned status =%d",status);
       }
       if(used){
          port_out->MixPushThisBuffer(buffer);
       }
       else{
          port_out->PushThisBuffer(buffer);
        }
    }
    //check the buffer from mix buffer queue,
    len = port_out->MixBufferQueueLength();
    for( OMX_U32 i=0; i <len; i++){
       buffer = port_out->MixPopBuffer();
       if(buffer == NULL)
          break;
       mVideoDecoder->GetNativeBufferStatus(buffer->pBuffer,&used);
        if(status != DECODE_SUCCESS){
          LOGW("GetNativeBufferStatus returned status =%d",status);
       }
       if(used){
          port_out->MixPushThisBuffer(buffer);
       }
       else{
          port_out->PushThisBuffer(buffer);
       }
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
    ret = FillRenderBuffer(pBuffers[OUTPORT_INDEX], 0);
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
            retains[OUTPORT_INDEX] = BUFFER_RETAIN_GETAGAIN;
            return OMX_ErrorNone;
        }
        else if (status != DECODE_SUCCESS && status != DECODE_FRAME_DROPPED) {
            if (checkFatalDecoderError(status)) {
                return TranslateDecodeStatus(status);
            } else {
                // For decoder errors that could be omitted,  not throw error and continue to decode.
                TranslateDecodeStatus(status);

                ((*pBuffers[OUTPORT_INDEX]))->nFilledLen = 0;
                retains[OUTPORT_INDEX] = BUFFER_RETAIN_GETAGAIN;
                return OMX_ErrorNone;
            }
        }
    }
    // drain the decoder output queue when in EOS state and fill the render buffer
    ret = FillRenderBuffer(pBuffers[OUTPORT_INDEX], ((*pBuffers[INPORT_INDEX]))->nFlags);

    if (ret == OMX_ErrorNotReady) {
        retains[OUTPORT_INDEX] = BUFFER_RETAIN_GETAGAIN;
        ret = OMX_ErrorNone;
    }

    return ret;
}

OMX_ERRORTYPE OMXVideoDecoderBase::PrepareConfigBuffer(VideoConfigBuffer *p) {
    // default config buffer preparation
    memset(p, 0, sizeof(VideoConfigBuffer));

    const OMX_PARAM_PORTDEFINITIONTYPE *paramPortDefinitionInput = this->ports[INPORT_INDEX]->GetPortDefinition();
    if (paramPortDefinitionInput == NULL) {
        return OMX_ErrorBadParameter;
    }

    if ( mNativeBufferMode) {
        LOGD("intel omx video decoder working in native buffer mode");
    }else{
        LOGD("intel omx video decoder working in raw nv12 mode ");
    }

    if( mNativeBufferMode){
        p->surfaceNumber = mOMXBufferHeaderTypePtrNum;
        for( int i=0; i < mOMXBufferHeaderTypePtrNum;i++){
            OMX_BUFFERHEADERTYPE *buffer_hdr = mOMXBufferHeaderTypePtrArray[i];
            p->graphicBufferHandler[i] = buffer_hdr->pBuffer;
            LOGV("PrepareConfigBuffer bufferid=%p,handle =%p",buffer_hdr,buffer_hdr->pBuffer);
        }
        p->flag |= USE_NATIVE_GRAPHIC_BUFFER;
        p->graphicBufferStride = mGraphicBufferStride;
        p->graphicBufferColorFormat = mGraphicBuffercolorformat;

        PortVideo *port = NULL;
        port = static_cast<PortVideo *>(this->ports[INPORT_INDEX]);
        OMX_PARAM_PORTDEFINITIONTYPE port_def;
        memcpy(&port_def,port->GetPortDefinition(),sizeof(port_def));

        if(port_def.format.video.pNativeWindow != NULL){
            p->nativeWindow = port_def.format.video.pNativeWindow;
            LOGD("NativeWindow = %p", p->nativeWindow);
        }

    }
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
    if (buffer->nFlags & OMX_BUFFERFLAG_ENDOFFRAME) {
        // TODO: OMX_BUFFERFLAG_ENDOFFRAME can be used to indicate end of a NAL unit.
        // setting this flag may cause corruption if buffer does not contain end-of-frame data.
        p->flag = HAS_COMPLETE_FRAME;
    }

    if(buffer->nFlags & OMX_BUFFERFLAG_SYNCFRAME) {
        p->flag |= IS_SYNC_FRAME;
    }

    *retain= BUFFER_RETAIN_NOT_RETAIN;
    return OMX_ErrorNone;
}

OMX_ERRORTYPE OMXVideoDecoderBase::FillRenderBuffer(OMX_BUFFERHEADERTYPE **pBuffer, OMX_U32 inportBufferFlags) {

    OMX_BUFFERHEADERTYPE *buffer = *pBuffer;
    OMX_BUFFERHEADERTYPE *buffer_orign = buffer;

    if (!mNativeBufferMode && buffer->pPlatformPrivate) {
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
            LOGI("EOS received");
            buffer->nFlags = OMX_BUFFERFLAG_EOS;
            return OMX_ErrorNone;
        }
        return OMX_ErrorNotReady;
    }

    if(mNativeBufferMode) {
        buffer = *pBuffer = mOMXBufferHeaderTypePtrArray[renderBuffer->acquirePos];
     }

    buffer->nFlags = OMX_BUFFERFLAG_ENDOFFRAME;
    buffer->nTimeStamp = renderBuffer->timeStamp;

    if (mNativeBufferMode) {

        PortBase *port_out = this->ports[OUTPORT_INDEX];
        //check orign buffer
        if(buffer_orign != buffer) {

            bool used = false;
            mVideoDecoder->GetNativeBufferStatus(buffer_orign->pBuffer,&used);
            if(used){
                port_out->MixPushThisBuffer(buffer_orign);
            }else{
                port_out->PushThisBuffer(buffer_orign);
            }

            //need pop  the returing buffer from mix used buffer queue
            OMX_U32 len = port_out->MixBufferQueueLength();
            OMX_BUFFERHEADERTYPE *temp = NULL;
            for(OMX_U32 i = 0 ; i < len; i++) {
                temp = port_out->MixPopBuffer();
                if(temp == NULL)
                    break;
                if(temp == buffer) {
                    LOGV("FillRenderBuffer Poped buffer = %p from mix queue",temp);
                    break;
                }
                else {
                    port_out->MixPushThisBuffer(temp);
                }
            }

            // make sure the render buffer has been moved out of bufferq
            len = port_out->BufferQueueLength();
            for(OMX_U32 i = 0; i < len; i++) {
                temp = port_out->PopBuffer();
                if(temp == NULL)
                    break;
                if(temp == buffer) {
                    LOGV("FillRenderBuffer Poped buffer = %p from buffer queue",temp);
                    break;
                }
                else {
                    port_out->PushThisBuffer(temp);
                }
            }
        }
        buffer->nFilledLen = sizeof(OMX_U8*);
    } else {
        MapRawNV12(renderBuffer, buffer->pBuffer + buffer->nOffset, buffer->nFilledLen);
        buffer->pPlatformPrivate = (void *)renderBuffer;
    }

    return OMX_ErrorNone;
}

OMX_ERRORTYPE OMXVideoDecoderBase::HandleFormatChange(void) {
    LOGW("Video format is changed.");
    if(mNativeBufferMode)
        return OMX_ErrorNone;
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

    LOGV("Original size = %lu x %lu, new size = %d x %d, cropped size = %d x %d",
        paramPortDefinitionInput.format.video.nFrameWidth,
        paramPortDefinitionInput.format.video.nFrameHeight,
        width, height, widthCropped, heightCropped);


    if (width == paramPortDefinitionInput.format.video.nFrameWidth &&
        height == paramPortDefinitionInput.format.video.nFrameHeight &&
        widthCropped == paramPortDefinitionOutput.format.video.nFrameWidth &&
        heightCropped == paramPortDefinitionOutput.format.video.nFrameHeight) {
        // reporting portsetting change may crash media player.
        LOGW("Change of portsetting is not reported as size is not changed.");
        return OMX_ErrorNone;
    }

    paramPortDefinitionInput.format.video.nFrameWidth = width;
    paramPortDefinitionInput.format.video.nFrameHeight = height;
    paramPortDefinitionInput.format.video.nStride = stride;
    paramPortDefinitionInput.format.video.nSliceHeight = sliceHeight;

    paramPortDefinitionOutput.format.video.nFrameWidth = widthCropped;
    paramPortDefinitionOutput.format.video.nFrameHeight = heightCropped;
    paramPortDefinitionOutput.format.video.nStride = strideCropped;
    paramPortDefinitionOutput.format.video.nSliceHeight = sliceHeightCropped;


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
    //AddHandler(PV_OMX_COMPONENT_CAPABILITY_TYPE_INDEX, GetCapabilityFlags, SetCapabilityFlags); 
    AddHandler(static_cast<OMX_INDEXTYPE>(OMX_IndexExtGetNativeBufferUsage),GetNativeBufferUsage,SetNativeBufferUsage);
    AddHandler(static_cast<OMX_INDEXTYPE>(OMX_IndexExtUseNativeBuffer),GetNativeBuffer,SetNativeBuffer);

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
     param->nUsage |= GRALLOC_USAGE_SW_WRITE_OFTEN;
     param->nUsage |= GRALLOC_USAGE_HW_TEXTURE;
     return OMX_ErrorNone;
}
OMX_ERRORTYPE OMXVideoDecoderBase::SetNativeBufferUsage(OMX_PTR pStructure) {
    OMX_ERRORTYPE ret;
    CHECK_SET_PARAM_STATE();
    return OMX_ErrorBadParameter;
}

OMX_ERRORTYPE OMXVideoDecoderBase::GetNativeBuffer(OMX_PTR pStructure) {
    OMX_ERRORTYPE ret;
    return OMX_ErrorBadParameter;
}
OMX_ERRORTYPE OMXVideoDecoderBase::SetNativeBuffer(OMX_PTR pStructure) {
    OMX_ERRORTYPE ret;
    CHECK_SET_PARAM_STATE();
    UseAndroidNativeBufferParams *param = (UseAndroidNativeBufferParams*)pStructure;
    CHECK_TYPE_HEADER(param);
    if(param->nPortIndex != OUTPORT_INDEX)
        return OMX_ErrorBadParameter;
    OMX_BUFFERHEADERTYPE *buf_hdr = NULL;
    ret = this->ports[OUTPORT_INDEX]->UseBuffer(&buf_hdr,OUTPORT_INDEX,param->pAppPrivate,sizeof(OMX_U8*),
                                      const_cast<OMX_U8*>(reinterpret_cast<const OMX_U8*>(param->nativeBuffer->handle)));
    if(ret != OMX_ErrorNone)
        return ret;
    if (mOMXBufferHeaderTypePtrNum >= MAX_GRAPHIC_NUM)
        return OMX_ErrorOverflow;
    mOMXBufferHeaderTypePtrArray[mOMXBufferHeaderTypePtrNum++] = buf_hdr;
    *(param->bufferHeader) = buf_hdr;
    if(!mGraphicBuffercolorformat) {
         mGraphicBuffercolorformat = param->nativeBuffer->format;
    }
    if(!mGraphicBufferStride) {
         mGraphicBufferStride = param->nativeBuffer->stride;
    }
    return OMX_ErrorNone;
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
        return OMX_ErrorUndefined;
    }

    vaImage.image_id = VA_INVALID_ID;
    // driver currently only supports NV12 and IYUV format.
    // byte_order information is from driver  and hard-coded here
    imageFormat.fourcc = VA_FOURCC_NV12;
    imageFormat.byte_order = VA_LSB_FIRST;
    imageFormat.bits_per_pixel = 16;
    vaStatus = vaCreateImage(
        renderBuffer->display,
        &imageFormat,
        width,
        height,
        &vaImage);
    if (vaStatus != VA_STATUS_SUCCESS) {
        return OMX_ErrorUndefined;
    }

    vaStatus = vaGetImage(
        renderBuffer->display,
        renderBuffer->surface,
        0,
        0,
        vaImage.width,
        vaImage.height,
        vaImage.image_id);
    if (vaStatus != VA_STATUS_SUCCESS) {
        return OMX_ErrorUndefined;
    }

    void *pBuf = NULL;
    vaStatus = vaMapBuffer(renderBuffer->display, vaImage.buf, &pBuf);
    if (vaStatus != VA_STATUS_SUCCESS) {
        return OMX_ErrorUndefined;
    }

    if (size == (int32_t)vaImage.data_size) {
        memcpy(rawData, pBuf, size);
    } else {
        // copy Y data
        uint8_t *src = (uint8_t*)pBuf;
        uint8_t *dst = rawData;
        int32_t row = 0;
        for (row = 0; row < height; row++) {
            memcpy(dst, src, width);
            dst += width;
            src += vaImage.pitches[0];
        }
        // copy interleaved V and  U data
        src = (uint8_t*)pBuf + vaImage.offsets[1];
        for (row = 0; row < height/2; row++) {
            memcpy(dst, src, width);
            dst += width;
            src += vaImage.pitches[1];
        }
    }
    // TODO: image may not get destroyed if error happens.
    if (vaImage.image_id != VA_INVALID_ID) {
        vaDestroyImage(renderBuffer->display, vaImage.image_id);
    }
    return OMX_ErrorNone;
}

OMX_ERRORTYPE OMXVideoDecoderBase::GetCapabilityFlags(OMX_PTR pStructure) {
#if 0
    OMX_ERRORTYPE ret;
    PV_OMXComponentCapabilityFlagsType *p = (PV_OMXComponentCapabilityFlagsType *)pStructure;

    CHECK_TYPE_HEADER(p);
    CHECK_PORT_INDEX_RANGE(p);

    p->iIsOMXComponentMultiThreaded = OMX_TRUE;
    p->iOMXComponentSupportsExternalInputBufferAlloc = OMX_TRUE;
    p->iOMXComponentSupportsExternalOutputBufferAlloc = OMX_TRUE;
    p->iOMXComponentSupportsMovableInputBuffers = OMX_TRUE;
    p->iOMXComponentSupportsPartialFrames = OMX_TRUE;
    p->iOMXComponentCanHandleIncompleteFrames = OMX_TRUE;
    p->iOMXComponentUsesNALStartCodes = OMX_FALSE;
    p->iOMXComponentUsesFullAVCFrames = OMX_FALSE;
#endif
    return OMX_ErrorNone;
}

OMX_ERRORTYPE OMXVideoDecoderBase::SetCapabilityFlags(OMX_PTR pStructure) {
    LOGE("SetCapabilityFlags is not supported.");
    return OMX_ErrorUnsupportedSetting;
}

