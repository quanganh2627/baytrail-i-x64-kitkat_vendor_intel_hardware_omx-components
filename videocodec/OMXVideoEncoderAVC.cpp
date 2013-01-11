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
#define LOG_TAG "OMXVideoEncoderAVC"
#include <utils/Log.h>
#include "OMXVideoEncoderAVC.h"
#include "IntelMetadataBuffer.h"

static const char *AVC_MIME_TYPE = "video/h264";

OMXVideoEncoderAVC::OMXVideoEncoderAVC() {
    BuildHandlerList();
    mVideoEncoder = createVideoEncoder(AVC_MIME_TYPE);
    if (!mVideoEncoder) LOGE("OMX_ErrorInsufficientResources");

    mAVCParams = new VideoParamsAVC();
    if (!mAVCParams) LOGE("OMX_ErrorInsufficientResources");
}

OMXVideoEncoderAVC::~OMXVideoEncoderAVC() {
    if(mAVCParams) {
        delete mAVCParams;
        mAVCParams = NULL;
    }
}

OMX_ERRORTYPE OMXVideoEncoderAVC::InitOutputPortFormatSpecific(OMX_PARAM_PORTDEFINITIONTYPE *paramPortDefinitionOutput) {
    // OMX_VIDEO_PARAM_AVCTYPE
    memset(&mParamAvc, 0, sizeof(mParamAvc));
    SetTypeHeader(&mParamAvc, sizeof(mParamAvc));
    mParamAvc.nPortIndex = OUTPORT_INDEX;
    mParamAvc.eProfile = OMX_VIDEO_AVCProfileBaseline;
    mParamAvc.eLevel = OMX_VIDEO_AVCLevel41;
    mParamAvc.nPFrames = 30;
    mParamAvc.nBFrames = 0;

    // OMX_NALSTREAMFORMATTYPE
    memset(&mNalStreamFormat, 0, sizeof(mNalStreamFormat));
    SetTypeHeader(&mNalStreamFormat, sizeof(mNalStreamFormat));
    mNalStreamFormat.nPortIndex = OUTPORT_INDEX;
    // TODO: check if this is desired Nalu Format
    mNalStreamFormat.eNaluFormat = OMX_NaluFormatStartCodesSeparateFirstHeader;
    //mNalStreamFormat.eNaluFormat = OMX_NaluFormatLengthPrefixedSeparateFirstHeader;
    // OMX_VIDEO_CONFIG_AVCINTRAPERIOD
    memset(&mConfigAvcIntraPeriod, 0, sizeof(mConfigAvcIntraPeriod));
    SetTypeHeader(&mConfigAvcIntraPeriod, sizeof(mConfigAvcIntraPeriod));
    mConfigAvcIntraPeriod.nPortIndex = OUTPORT_INDEX;
    // TODO: need to be populated from Video Encoder
    mConfigAvcIntraPeriod.nIDRPeriod = 1;
    mConfigAvcIntraPeriod.nPFrames = 30;

    // OMX_VIDEO_CONFIG_NALSIZE
    memset(&mConfigNalSize, 0, sizeof(mConfigNalSize));
    SetTypeHeader(&mConfigNalSize, sizeof(mConfigNalSize));
    mConfigNalSize.nPortIndex = OUTPORT_INDEX;
    mConfigNalSize.nNaluBytes = 0;

    // OMX_VIDEO_PARAM_INTEL_AVCVUI
    memset(&mParamIntelAvcVui, 0, sizeof(mParamIntelAvcVui));
    SetTypeHeader(&mParamIntelAvcVui, sizeof(mParamIntelAvcVui));
    mParamIntelAvcVui.nPortIndex = OUTPORT_INDEX;
    mParamIntelAvcVui.bVuiGeneration = OMX_FALSE;

    // OMX_VIDEO_CONFIG_INTEL_SLICE_NUMBERS
    memset(&mConfigIntelSliceNumbers, 0, sizeof(mConfigIntelSliceNumbers));
    SetTypeHeader(&mConfigIntelSliceNumbers, sizeof(mConfigIntelSliceNumbers));
    mConfigIntelSliceNumbers.nPortIndex = OUTPORT_INDEX;
    mConfigIntelSliceNumbers.nISliceNumber = 2;
    mConfigIntelSliceNumbers.nPSliceNumber = 2;

    // Override OMX_PARAM_PORTDEFINITIONTYPE
    paramPortDefinitionOutput->nBufferCountActual = OUTPORT_ACTUAL_BUFFER_COUNT;
    paramPortDefinitionOutput->nBufferCountMin = OUTPORT_MIN_BUFFER_COUNT;
    paramPortDefinitionOutput->nBufferSize = OUTPORT_BUFFER_SIZE;
    paramPortDefinitionOutput->format.video.cMIMEType = (OMX_STRING)AVC_MIME_TYPE;
    paramPortDefinitionOutput->format.video.eCompressionFormat = OMX_VIDEO_CodingAVC;

    // Override OMX_VIDEO_PARAM_PROFILELEVELTYPE
    // TODO: check if profile/level supported is correct
    mParamProfileLevel.eProfile = mParamAvc.eProfile;
    mParamProfileLevel.eLevel = mParamAvc.eLevel;

    // Override OMX_VIDEO_PARAM_BITRATETYPE
    mParamBitrate.nTargetBitrate = 192000;

    // Override OMX_VIDEO_CONFIG_INTEL_BITRATETYPE
    mConfigIntelBitrate.nInitialQP = 0;  // Initial QP for I frames

    return OMX_ErrorNone;
}

OMX_ERRORTYPE OMXVideoEncoderAVC::SetVideoEncoderParam(void) {

    Encode_Status ret = ENCODE_SUCCESS;
    LOGV("OMXVideoEncoderAVC::SetVideoEncoderParam");

    if (!mEncoderParams) {
        LOGE("NULL pointer: mEncoderParams");
        return OMX_ErrorBadParameter;
    }

    mVideoEncoder->getParameters(mEncoderParams);
    if (mParamAvc.eProfile == OMX_VIDEO_AVCProfileBaseline) {
        mEncoderParams->profile = (VAProfile)VAProfileH264Baseline;
        mEncoderParams->intraPeriod = mParamAvc.nPFrames;  //intraperiod
    } else if (mParamAvc.eProfile == OMX_VIDEO_AVCProfileHigh) {
        mEncoderParams->profile = (VAProfile)VAProfileH264High;
        mEncoderParams->intraPeriod = mParamAvc.nPFrames + mParamAvc.nBFrames; //intraperiod
    }
    // 0 - all luma and chroma block edges of the slice are filtered
    // 1 - deblocking is disabled for all block edges of the slice
    // 2 - all luma and chroma block edges of the slice are filtered
    // with exception of the block edges that coincide with slice boundaries
    mEncoderParams->disableDeblocking = 0;


    OMXVideoEncoderBase::SetVideoEncoderParam();

    mVideoEncoder->getParameters(mAVCParams);
    if(mParamIntelAvcVui.bVuiGeneration == OMX_TRUE) {
        mAVCParams->VUIFlag = 1;
    }
    // For resolution below VGA, single core can hit the performance target and provide VQ gain
    if (mEncoderParams->resolution.width <= 640 && mEncoderParams->resolution.height <= 480) {
        mConfigIntelSliceNumbers.nISliceNumber = 1;
        mConfigIntelSliceNumbers.nPSliceNumber = 1;
    }
    mAVCParams->sliceNum.iSliceNum = mConfigIntelSliceNumbers.nISliceNumber;
    mAVCParams->sliceNum.pSliceNum = mConfigIntelSliceNumbers.nPSliceNumber;
    mAVCParams->maxSliceSize = mConfigNalSize.nNaluBytes * 8;
    if (mEncoderParams->intraPeriod == 0) {
        mAVCParams->idrInterval = 0;
        mAVCParams->ipPeriod = 0;
    } else {
        mAVCParams->idrInterval = mConfigAvcIntraPeriod.nIDRPeriod; //idrinterval
        if (mParamAvc.eProfile == OMX_VIDEO_AVCProfileBaseline) {
            mAVCParams->ipPeriod = 1;   //ipperiod
        } else if (mParamAvc.eProfile == OMX_VIDEO_AVCProfileHigh) {
            mAVCParams->ipPeriod = mEncoderParams->intraPeriod / mParamAvc.nPFrames; //ipperiod
        }
    }
    ret = mVideoEncoder ->setParameters(mAVCParams);
    CHECK_ENCODE_STATUS("setParameters");

    LOGV("VUIFlag = %d\n", mAVCParams->VUIFlag);
    LOGV("sliceNum.iSliceNum = %d\n", mAVCParams->sliceNum.iSliceNum);
    LOGV("sliceNum.pSliceNum = %d\n", mAVCParams->sliceNum.pSliceNum);
    LOGV("maxSliceSize = %d\n ", mAVCParams->maxSliceSize);
    LOGV("intraPeriod = %d\n ", mEncoderParams->intraPeriod);
    LOGV("idrInterval = %d\n ", mAVCParams->idrInterval);
    LOGV("ipPeriod = %d\n ", mAVCParams->ipPeriod);
    return OMX_ErrorNone;
}

OMX_ERRORTYPE OMXVideoEncoderAVC::ProcessorInit(void) {
    mFirstFrame = OMX_TRUE;
    mInputPictureCount = 0;
    mFrameEncodedCount = 0;
    return  OMXVideoEncoderBase::ProcessorInit();
}

OMX_ERRORTYPE OMXVideoEncoderAVC::ProcessorDeinit(void) {
    return OMXVideoEncoderBase::ProcessorDeinit();
}

OMX_ERRORTYPE OMXVideoEncoderAVC::ProcessorStop(void) {
    OMX_BUFFERHEADERTYPE *omxbuf = NULL;

    while(!mBFrameList.empty()) {
        omxbuf = * mBFrameList.begin();
        this->ports[INPORT_INDEX]->ReturnThisBuffer(omxbuf);
        mBFrameList.erase(mBFrameList.begin());
    }

    return OMXVideoEncoderBase::ProcessorStop();
}

OMX_ERRORTYPE OMXVideoEncoderAVC::ProcessorPreEmptyBuffer(OMX_BUFFERHEADERTYPE* buffer) {
    OMX_U32 EncodeInfo = 0;
    OMX_U32 EncodeFrameType = 0;

    uint32_t poc = 0;
    uint32_t idrPeriod = mAVCParams->idrInterval;
    uint32_t IntraPeriod = mEncoderParams->intraPeriod; /*6*/
    uint32_t IpPeriod = mAVCParams->ipPeriod;  /*3 */
    bool BFrameEnabled = IpPeriod > 1;

    LOGV("ProcessorPreEmptyBuffer idrPeriod=%d, IntraPeriod=%d, IpPeriod=%d, BFrameEnabled=%d\n", idrPeriod, IntraPeriod, IpPeriod, BFrameEnabled);

    //decide frame type, refer Merrifield Video Encoder Driver HLD Chapter 3.15
    if (idrPeriod == 0)
        poc = mInputPictureCount;
    else if (BFrameEnabled)
        poc = mInputPictureCount % (IntraPeriod*idrPeriod + 1);
    else
        poc = mInputPictureCount % (IntraPeriod*idrPeriod);

    if (poc == 0 /*IDR*/) {
            EncodeFrameType = F_IDR;
    } else if (IntraPeriod == 0) {
            EncodeFrameType = F_I;
    }else if ((poc > IpPeriod) && ((poc - IpPeriod) % IntraPeriod == 0))/*I*/{
            EncodeFrameType = F_I;
            if (BFrameEnabled)
                SET_CO(EncodeInfo, CACHE_POP);
    } else if ((poc % IpPeriod == 0) /*P*/ || (buffer->nFlags & OMX_BUFFERFLAG_EOS)/*EOS,always P*/) {
            EncodeFrameType = F_P;
            if (BFrameEnabled)
                SET_CO(EncodeInfo, CACHE_POP);
    } else { /*B*/
            EncodeFrameType = F_B;
            SET_CO(EncodeInfo, CACHE_PUSH);
    }

    SET_FT(EncodeInfo, EncodeFrameType);
    SET_FC(EncodeInfo, mInputPictureCount);

    buffer->pPlatformPrivate = (OMX_PTR) EncodeInfo;

    LOGV("ProcessorPreEmptyBuffer Frame %d, Type %s, EncodeInfo %x\n", mInputPictureCount, FrameTypeStr[EncodeFrameType], EncodeInfo);

    mInputPictureCount ++;
    return OMX_ErrorNone;
}

OMX_ERRORTYPE OMXVideoEncoderAVC::ProcessCacheOperation(
    OMX_BUFFERHEADERTYPE **buffers,
    buffer_retain_t *retains,
    Encode_Info *pInfo) {

    /* Check and do cache operation
    */
    if (pInfo->CacheOperation == CACHE_NONE) {
        if (buffers[INPORT_INDEX]->nFlags & OMX_BUFFERFLAG_EOS)
            pInfo->EndOfEncode = true;

    } else if (pInfo->CacheOperation == CACHE_PUSH) {
        mBFrameList.push_front(buffers[INPORT_INDEX]);
        retains[INPORT_INDEX] = BUFFER_RETAIN_CACHE;
        retains[OUTPORT_INDEX] = BUFFER_RETAIN_GETAGAIN;

    } else if (pInfo->CacheOperation == CACHE_POP) {
        pInfo->NotStopFrame = true;  //it is also a nstop frame

        OMX_BUFFERHEADERTYPE *omxbuf = NULL;
        uint32_t i = 0;

        LOGV("BFrameList size = %d\n", mBFrameList.size());

        while(!mBFrameList.empty()) {
            omxbuf = *mBFrameList.begin();

            if (buffers[INPORT_INDEX]->nFlags & OMX_BUFFERFLAG_EOS && i == 0 )  {
                //this is final encode frame, make EOE
                uint32_t tmp = (uint32_t) omxbuf->pPlatformPrivate;
                tmp |= ENC_EOE;
                omxbuf->pPlatformPrivate = (OMX_PTR) tmp;
            } else {
                //all these frames except final B frame in miniGOP can't be stopped at any time
                //to avoid not breaking miniGOP integrity
                if (i > 0) {
                    uint32_t tmp = (uint32_t) omxbuf->pPlatformPrivate;
                    tmp |= ENC_NSTOP;
                    omxbuf->pPlatformPrivate = (OMX_PTR) tmp;
                }
            }
            ports[INPORT_INDEX]->RetainThisBuffer(omxbuf, false); //push bufferq head

            mBFrameList.erase(mBFrameList.begin()); //clear it from internal queue
            i++;
        }

    } else if (pInfo->CacheOperation == CACHE_RESET) {
//        mBFrameList.clear();
    }

    pInfo->CacheOperation = CACHE_NONE;

    LOGV("ProcessCacheOperation OK\n");
    return OMX_ErrorNone;
}

OMX_ERRORTYPE OMXVideoEncoderAVC::ProcessDataRetrieve(
    OMX_BUFFERHEADERTYPE **buffers,
    buffer_retain_t *retains,
    Encode_Info *pInfo) {

    OMX_NALUFORMATSTYPE NaluFormat = mNalStreamFormat.eNaluFormat;

    if (mStoreMetaDataInBuffers)
        NaluFormat = OMX_NaluFormatLengthPrefixedSeparateFirstHeader;

    VideoEncOutputBuffer outBuf;
    outBuf.data = buffers[OUTPORT_INDEX]->pBuffer + buffers[OUTPORT_INDEX]->nOffset;
    outBuf.bufferSize = buffers[OUTPORT_INDEX]->nAllocLen - buffers[OUTPORT_INDEX]->nOffset;
    outBuf.dataSize = 0;
    outBuf.remainingSize = 0;
    outBuf.flag = 0;
    outBuf.timeStamp = 0;

    switch (NaluFormat) {
        case OMX_NaluFormatStartCodes:
            outBuf.format = OUTPUT_EVERYTHING;
            break;

        case OMX_NaluFormatOneNaluPerBuffer:
            outBuf.format = OUTPUT_ONE_NAL;
            break;

        case OMX_NaluFormatStartCodesSeparateFirstHeader:
        case OMX_NaluFormatLengthPrefixedSeparateFirstHeader:
            if(mFirstFrame) {
                LOGV("FirstFrame to output codec data\n");
                outBuf.format = OUTPUT_CODEC_DATA;
            } else {
                if (NaluFormat == OMX_NaluFormatStartCodesSeparateFirstHeader)
                    outBuf.format = OUTPUT_EVERYTHING;
                else
                    outBuf.format = OUTPUT_LENGTH_PREFIXED;
            }
            break;

        default:
            return OMX_ErrorUndefined;
    }

    //start getOutput
    Encode_Status ret = mVideoEncoder->getOutput(&outBuf);

    if (ret < ENCODE_SUCCESS) {
        LOGE("libMIX getOutput Failed. ret = 0x%08x, drop this frame\n", ret);
        outBuf.dataSize = 0;
        outBuf.flag |= ENCODE_BUFFERFLAG_ENDOFFRAME;
//        return OMX_ErrorUndefined;

    } else if (ret == ENCODE_BUFFER_TOO_SMALL)
        return OMX_ErrorUndefined; // Return code could not be ENCODE_BUFFER_TOO_SMALL, or we will have dead lock issue

    LOGV("libMIX getOutput data size= %d, flag=0x%08x", outBuf.dataSize, outBuf.flag);
    OMX_U32 outfilledlen = outBuf.dataSize;
    OMX_S64 outtimestamp = outBuf.timeStamp;
    OMX_U32 outflags = 0;

    //if codecconfig
    if (outBuf.flag & ENCODE_BUFFERFLAG_CODECCONFIG)
        outflags |= OMX_BUFFERFLAG_CODECCONFIG;

    //if syncframe
    if (outBuf.flag & ENCODE_BUFFERFLAG_SYNCFRAME)
        outflags |= OMX_BUFFERFLAG_SYNCFRAME;

    //if eos
    if (outBuf.flag & ENCODE_BUFFERFLAG_ENDOFSTREAM)
        outflags |= OMX_BUFFERFLAG_EOS;

    //if full encoded data retrieved
    if(outBuf.flag & ENCODE_BUFFERFLAG_ENDOFFRAME) {
        LOGV("Output a complete Frame done\n");
        outflags |= OMX_BUFFERFLAG_ENDOFFRAME;

        if ((NaluFormat == OMX_NaluFormatStartCodesSeparateFirstHeader
             || NaluFormat == OMX_NaluFormatLengthPrefixedSeparateFirstHeader ) && mFirstFrame ) {
            // This input buffer need to be gotten again
            retains[INPORT_INDEX] = BUFFER_RETAIN_GETAGAIN;
            mFirstFrame = OMX_FALSE;

        } else {
            pInfo->DataRetrieved = true;
            ports[INPORT_INDEX]->ReturnAllRetainedBuffers();  //return last all retained frames
            if (outBuf.flag & ENCODE_BUFFERFLAG_ENDOFSTREAM)
                retains[INPORT_INDEX] = BUFFER_RETAIN_NOT_RETAIN;
            else
                retains[INPORT_INDEX] = BUFFER_RETAIN_ACCUMULATE;   //retain current frame

            mFrameOutputCount  ++;
        }
    } else //not complete output all encoded data, push again to continue output
        retains[INPORT_INDEX] = BUFFER_RETAIN_GETAGAIN;

    LOGV("OMX output buffer = %p:%d, flag = %x, ts=%lld", buffers[OUTPORT_INDEX]->pBuffer, outfilledlen, outflags, outtimestamp);

    if (outfilledlen > 0) {
        retains[OUTPORT_INDEX] = BUFFER_RETAIN_NOT_RETAIN;
        buffers[OUTPORT_INDEX]->nFilledLen = outfilledlen;
        buffers[OUTPORT_INDEX]->nTimeStamp = outtimestamp;
        buffers[OUTPORT_INDEX]->nFlags = outflags;
        if (outBuf.flag & ENCODE_BUFFERFLAG_NSTOPFRAME)
            buffers[OUTPORT_INDEX]->pPlatformPrivate = (OMX_PTR) 0x00000001;  //indicate it is nstop frame
    }
    else
        retains[OUTPORT_INDEX] = BUFFER_RETAIN_GETAGAIN;

    LOGV("ProcessDataRetrieve OK\n");
    return OMX_ErrorNone;
}

OMX_ERRORTYPE OMXVideoEncoderAVC::ProcessorProcess(
    OMX_BUFFERHEADERTYPE **buffers,
    buffer_retain_t *retains,
    OMX_U32 numberBuffers) {

    OMX_ERRORTYPE oret = OMX_ErrorNone;
    Encode_Status ret = ENCODE_SUCCESS;

    VideoEncRawBuffer inBuf;

    inBuf.data = buffers[INPORT_INDEX]->pBuffer + buffers[INPORT_INDEX]->nOffset;
    inBuf.size = buffers[INPORT_INDEX]->nFilledLen;
    inBuf.flag = 0;
    inBuf.timeStamp = buffers[INPORT_INDEX]->nTimeStamp;

    if (buffers[INPORT_INDEX]->nFlags & OMX_BUFFERFLAG_EOS) {
        LOGV("%s(),%d: got OMX_BUFFERFLAG_EOS\n", __func__, __LINE__);
        if(inBuf.size<=0 || inBuf.data == NULL) {
            LOGE("The Input buf size is 0 or buf is NULL, return with no error\n");
            retains[INPORT_INDEX] = BUFFER_RETAIN_NOT_RETAIN;
            return OMX_ErrorNone;
        }
    }

    if(inBuf.size<=0 || inBuf.data == NULL) {
        LOGE("The Input buf size is 0 or buf is NULL, return with error\n");
        return OMX_ErrorBadParameter;
    }

    LOGV("Input OMX Buffer = 0x%x, size=%d, ts = %lld", inBuf.data, inBuf.size, buffers[INPORT_INDEX]->nTimeStamp);

    //get frame encode info
    Encode_Info eInfo;
    uint32_t encodeInfo     = (uint32_t) buffers[INPORT_INDEX]->pPlatformPrivate;
    eInfo.FrameType            = GET_FT(encodeInfo);
    eInfo.EncodeComplete    = encodeInfo & ENC_EC;
    eInfo.DataRetrieved       = encodeInfo & ENC_DR;
    eInfo.CacheOperation    = GET_CO(encodeInfo);
    eInfo.EndOfEncode        = encodeInfo & ENC_EOE;
    eInfo.NotStopFrame      = encodeInfo & ENC_NSTOP;
    eInfo.FrameCount         = GET_FC(encodeInfo);

    LOGV("ProcessorProcess Frame %d, type:%s, EC:%d, DR:%d, CO:%s, EOE=%d\n",
            eInfo.FrameCount , FrameTypeStr[eInfo.FrameType], eInfo.EncodeComplete,
            eInfo.DataRetrieved, CacheOperationStr[eInfo.CacheOperation], eInfo.EndOfEncode );

    //for live effect
    if (bAndroidOpaqueFormat)
        mCurHandle = rgba2nv12conversion(buffers[INPORT_INDEX]);

    if (eInfo.CacheOperation == CACHE_PUSH) {
        ProcessCacheOperation(buffers, retains, &eInfo);
        //nothing should be done in this case, just store status and return
        goto exit;
    }else
        ProcessCacheOperation(buffers, retains, &eInfo);

    /* Check encode state, if not, call libMIX encode()
    */
    if(!eInfo.EncodeComplete) {
        // encode and setConfig need to be thread safe
        if (eInfo.EndOfEncode)
            inBuf.flag |= ENCODE_BUFFERFLAG_ENDOFSTREAM;
        if (eInfo.NotStopFrame)
            inBuf.flag |= ENCODE_BUFFERFLAG_NSTOPFRAME;
        inBuf.type = (FrameType) eInfo.FrameType;

        pthread_mutex_lock(&mSerializationLock);
        ret = mVideoEncoder->encode(&inBuf);
        pthread_mutex_unlock(&mSerializationLock);
        CHECK_ENCODE_STATUS("encode");
        eInfo.EncodeComplete = true;

        mFrameEncodedCount ++;
        if (mFrameEncodedCount == 2) {//not getoutput for second encode frame to keep in async mode
            eInfo.DataRetrieved = true;
            retains[INPORT_INDEX] = BUFFER_RETAIN_ACCUMULATE;
            retains[OUTPORT_INDEX] = BUFFER_RETAIN_GETAGAIN;
        }
    }

    /* Check encode data retrieve state, if not complete output, continue call libMIX getOutput()
    */
    if (!eInfo.DataRetrieved)
        oret = ProcessDataRetrieve(buffers, retains, &eInfo);

    /* Check EOE state, if yes, this is final encode frame, need to push this buffer again
         to call getOutput again for final output
    */
    if (eInfo.EndOfEncode && eInfo.EncodeComplete && eInfo.DataRetrieved) {
        eInfo.DataRetrieved = false;
        eInfo.EndOfEncode = false;
        retains[INPORT_INDEX] = BUFFER_RETAIN_GETAGAIN;
    }

#if 0
    if (avcEncParamIntelBitrateType.eControlRate != OMX_Video_Intel_ControlRateVideoConferencingMode) {
        if (oret == (OMX_ERRORTYPE) OMX_ErrorIntelExtSliceSizeOverflow) {
            oret = OMX_ErrorNone;
        }
    }
#endif

exit:

    if (bAndroidOpaqueFormat && buffers[INPORT_INDEX]->nFilledLen != 0) {
        // Restore input buffer's content
        if (mCurHandle < 0)
            return OMX_ErrorUndefined;

        buffers[INPORT_INDEX]->nFilledLen = 4 + sizeof(buffer_handle_t);
        memcpy(buffers[INPORT_INDEX]->pBuffer, mBufferHandleMaps[mCurHandle].backBuffer,
                buffers[INPORT_INDEX]->nFilledLen);
    }

    /* restore all states into input OMX buffer
    */
    if (eInfo.EncodeComplete)
        encodeInfo |= ENC_EC;
    else
        encodeInfo &= ~ENC_EC;

    if (eInfo.DataRetrieved)
        encodeInfo |= ENC_DR;
    else
        encodeInfo &= ~ENC_DR;

    if (eInfo.EndOfEncode)
        encodeInfo |= ENC_EOE;
    else
        encodeInfo &= ~ENC_EOE;

    if (eInfo.NotStopFrame)
        encodeInfo |= ENC_NSTOP;
    else
        encodeInfo &= ~ENC_NSTOP;

    SET_CO(encodeInfo, eInfo.CacheOperation);
    buffers[INPORT_INDEX]->pPlatformPrivate = (OMX_PTR) encodeInfo;

    return oret;

}

OMX_ERRORTYPE OMXVideoEncoderAVC::BuildHandlerList(void) {
    OMXVideoEncoderBase::BuildHandlerList();
    AddHandler(OMX_IndexParamVideoAvc, GetParamVideoAvc, SetParamVideoAvc);
    AddHandler((OMX_INDEXTYPE)OMX_IndexParamNalStreamFormat, GetParamNalStreamFormat, SetParamNalStreamFormat);
    AddHandler((OMX_INDEXTYPE)OMX_IndexParamNalStreamFormatSupported, GetParamNalStreamFormatSupported, SetParamNalStreamFormatSupported);
    AddHandler((OMX_INDEXTYPE)OMX_IndexParamNalStreamFormatSelect, GetParamNalStreamFormatSelect, SetParamNalStreamFormatSelect);
    AddHandler(OMX_IndexConfigVideoAVCIntraPeriod, GetConfigVideoAVCIntraPeriod, SetConfigVideoAVCIntraPeriod);
    AddHandler(OMX_IndexConfigVideoNalSize, GetConfigVideoNalSize, SetConfigVideoNalSize);
    AddHandler((OMX_INDEXTYPE)OMX_IndexConfigIntelSliceNumbers, GetConfigIntelSliceNumbers, SetConfigIntelSliceNumbers);
    AddHandler((OMX_INDEXTYPE)OMX_IndexParamIntelAVCVUI, GetParamIntelAVCVUI, SetParamIntelAVCVUI);
    AddHandler((OMX_INDEXTYPE)OMX_IndexParamVideoBytestream, GetParamVideoBytestream, SetParamVideoBytestream);
    AddHandler((OMX_INDEXTYPE)OMX_IndexParamVideoProfileLevelQuerySupported, GetParamVideoProfileLevelQuerySupported, SetParamVideoProfileLevelQuerySupported);
    return OMX_ErrorNone;
}

OMX_ERRORTYPE OMXVideoEncoderAVC::GetParamVideoProfileLevelQuerySupported(OMX_PTR pStructure) {
    OMX_ERRORTYPE ret;
    OMX_VIDEO_PARAM_PROFILELEVELTYPE *p = (OMX_VIDEO_PARAM_PROFILELEVELTYPE *)pStructure;
    CHECK_TYPE_HEADER(p);
    CHECK_PORT_INDEX(p, OUTPORT_INDEX);

    struct ProfileLevelTable {
        OMX_U32 profile;
        OMX_U32 level;
    } plTable[] = {
        {OMX_VIDEO_AVCProfileBaseline, OMX_VIDEO_AVCLevel41},
//        {OMX_VIDEO_AVCProfileHigh, OMX_VIDEO_AVCLevel41},
    };

    OMX_U32 count = sizeof(plTable)/sizeof(ProfileLevelTable);
    CHECK_ENUMERATION_RANGE(p->nProfileIndex,count);

    p->eProfile = plTable[p->nProfileIndex].profile;
    p->eLevel = plTable[p->nProfileIndex].level;

    return OMX_ErrorNone;
}

OMX_ERRORTYPE OMXVideoEncoderAVC::SetParamVideoProfileLevelQuerySupported(OMX_PTR pStructure) {
    LOGW("SetParamVideoAVCProfileLevel is not supported.");
    return OMX_ErrorUnsupportedSetting;
}

OMX_ERRORTYPE OMXVideoEncoderAVC::GetParamVideoAvc(OMX_PTR pStructure) {
    OMX_ERRORTYPE ret;
    OMX_VIDEO_PARAM_AVCTYPE *p = (OMX_VIDEO_PARAM_AVCTYPE *)pStructure;
    CHECK_TYPE_HEADER(p);
    CHECK_PORT_INDEX(p, OUTPORT_INDEX);

    memcpy(p, &mParamAvc, sizeof(*p));
    return OMX_ErrorNone;
}

OMX_ERRORTYPE OMXVideoEncoderAVC::SetParamVideoAvc(OMX_PTR pStructure) {
    OMX_ERRORTYPE ret;
    OMX_VIDEO_PARAM_AVCTYPE *p = (OMX_VIDEO_PARAM_AVCTYPE *)pStructure;
    CHECK_TYPE_HEADER(p);
    CHECK_PORT_INDEX(p, OUTPORT_INDEX);
    CHECK_SET_PARAM_STATE();

    if(p->bEnableASO == OMX_TRUE)
        return OMX_ErrorUnsupportedSetting;

    if(p->bEnableFMO == OMX_TRUE)
        return OMX_ErrorUnsupportedSetting;

    if(p->bEnableUEP == OMX_TRUE)
        return OMX_ErrorUnsupportedSetting;

    if(p->bEnableRS == OMX_TRUE)
        return OMX_ErrorUnsupportedSetting;

    // TODO: do we need to check if port is enabled?
    // TODO: see SetPortAvcParam implementation - Can we make simple copy????
    memcpy(&mParamAvc, p, sizeof(mParamAvc));
    return OMX_ErrorNone;
}

OMX_ERRORTYPE OMXVideoEncoderAVC::GetParamNalStreamFormat(OMX_PTR pStructure) {
    OMX_ERRORTYPE ret;
    OMX_NALSTREAMFORMATTYPE *p = (OMX_NALSTREAMFORMATTYPE *)pStructure;

    CHECK_TYPE_HEADER(p);
    CHECK_PORT_INDEX(p, OUTPORT_INDEX);
    // TODO: check if this is desired format
    p->eNaluFormat = mNalStreamFormat.eNaluFormat; //OMX_NaluFormatStartCodes;
    return OMX_ErrorNone;
}

OMX_ERRORTYPE OMXVideoEncoderAVC::SetParamNalStreamFormat(OMX_PTR pStructure) {
    OMX_ERRORTYPE ret;
    OMX_NALSTREAMFORMATTYPE *p = (OMX_NALSTREAMFORMATTYPE *)pStructure;

    CHECK_TYPE_HEADER(p);
    CHECK_PORT_INDEX(p, OUTPORT_INDEX);
    LOGV("p->eNaluFormat =%d\n",p->eNaluFormat);
    if(p->eNaluFormat != OMX_NaluFormatStartCodes &&
            p->eNaluFormat != OMX_NaluFormatStartCodesSeparateFirstHeader &&
            p->eNaluFormat != OMX_NaluFormatOneNaluPerBuffer &&
            p->eNaluFormat != OMX_NaluFormatLengthPrefixedSeparateFirstHeader) {
        LOGE("Format not support\n");
        return OMX_ErrorUnsupportedSetting;
    }
    mNalStreamFormat.eNaluFormat = p->eNaluFormat;
    return OMX_ErrorNone;
}

OMX_ERRORTYPE OMXVideoEncoderAVC::GetParamNalStreamFormatSupported(OMX_PTR pStructure) {
    OMX_ERRORTYPE ret;
    OMX_NALSTREAMFORMATTYPE *p = (OMX_NALSTREAMFORMATTYPE *)pStructure;

    CHECK_TYPE_HEADER(p);
    CHECK_PORT_INDEX(p, OUTPORT_INDEX);
    p->eNaluFormat = (OMX_NALUFORMATSTYPE)
                     (OMX_NaluFormatStartCodes |
                      OMX_NaluFormatStartCodesSeparateFirstHeader |
                      OMX_NaluFormatOneNaluPerBuffer|
                      OMX_NaluFormatLengthPrefixedSeparateFirstHeader);

    // TODO: check if this is desired format
    // OMX_NaluFormatFourByteInterleaveLength |
    // OMX_NaluFormatZeroByteInterleaveLength);
    return OMX_ErrorNone;
}

OMX_ERRORTYPE OMXVideoEncoderAVC::SetParamNalStreamFormatSupported(OMX_PTR pStructure) {
    LOGW("SetParamNalStreamFormatSupported is not supported.");
    return OMX_ErrorUnsupportedSetting;
}

OMX_ERRORTYPE OMXVideoEncoderAVC::GetParamNalStreamFormatSelect(OMX_PTR pStructure) {
    LOGW("GetParamNalStreamFormatSelect is not supported.");
    return OMX_ErrorUnsupportedSetting;
}

OMX_ERRORTYPE OMXVideoEncoderAVC::SetParamNalStreamFormatSelect(OMX_PTR pStructure) {
    OMX_ERRORTYPE ret;
    OMX_NALSTREAMFORMATTYPE *p = (OMX_NALSTREAMFORMATTYPE *)pStructure;
    CHECK_TYPE_HEADER(p);
    CHECK_PORT_INDEX(p, OUTPORT_INDEX);

    // return OMX_ErrorIncorrectStateOperation if not in Loaded state
    CHECK_SET_PARAM_STATE();

    if (p->eNaluFormat != OMX_NaluFormatStartCodes &&
            p->eNaluFormat != OMX_NaluFormatStartCodesSeparateFirstHeader &&
            p->eNaluFormat != OMX_NaluFormatOneNaluPerBuffer&&
            p->eNaluFormat != OMX_NaluFormatLengthPrefixedSeparateFirstHeader) {
        //p->eNaluFormat != OMX_NaluFormatFourByteInterleaveLength &&
        //p->eNaluFormat != OMX_NaluFormatZeroByteInterleaveLength) {
        // TODO: check if this is desried
        return OMX_ErrorBadParameter;
    }

    mNalStreamFormat = *p;
    return OMX_ErrorNone;
}

OMX_ERRORTYPE OMXVideoEncoderAVC::GetConfigVideoAVCIntraPeriod(OMX_PTR pStructure) {
    OMX_ERRORTYPE ret;
    OMX_VIDEO_CONFIG_AVCINTRAPERIOD *p = (OMX_VIDEO_CONFIG_AVCINTRAPERIOD *)pStructure;

    CHECK_TYPE_HEADER(p);
    CHECK_PORT_INDEX(p, OUTPORT_INDEX);
    // TODO: populate mConfigAvcIntraPeriod from VideoEncoder
    // return OMX_ErrorNotReady if VideoEncoder is not created.
    memcpy(p, &mConfigAvcIntraPeriod, sizeof(*p));
    return OMX_ErrorNone;
}

OMX_ERRORTYPE OMXVideoEncoderAVC::SetConfigVideoAVCIntraPeriod(OMX_PTR pStructure) {
    OMX_ERRORTYPE ret;
    Encode_Status retStatus = ENCODE_SUCCESS;
    OMX_VIDEO_CONFIG_AVCINTRAPERIOD *p = (OMX_VIDEO_CONFIG_AVCINTRAPERIOD *)pStructure;
    CHECK_TYPE_HEADER(p);
    CHECK_PORT_INDEX(p, OUTPORT_INDEX);

    // set in either Loaded state (ComponentSetParam) or Executing state (ComponentSetConfig)
    mConfigAvcIntraPeriod = *p;

    // return OMX_ErrorNone if not in Executing state
    // TODO:  return OMX_ErrorIncorrectStateOperation?
    CHECK_SET_CONFIG_STATE();

    // TODO: apply AVC Intra Period configuration in Executing state
    VideoConfigAVCIntraPeriod avcIntraPreriod;
    avcIntraPreriod.intraPeriod = mConfigAvcIntraPeriod.nPFrames;
    if (avcIntraPreriod.intraPeriod == 0) {
        avcIntraPreriod.idrInterval = 0;
        avcIntraPreriod.ipPeriod = 0;
    } else {
        avcIntraPreriod.idrInterval = mConfigAvcIntraPeriod.nIDRPeriod;
        if (mParamAvc.eProfile == OMX_VIDEO_AVCProfileBaseline) {
            avcIntraPreriod.ipPeriod = 1;
        } else if (mParamAvc.eProfile == OMX_VIDEO_AVCProfileHigh) {
            avcIntraPreriod.ipPeriod = avcIntraPreriod.intraPeriod / mParamAvc.nPFrames;
        }
    }
    retStatus = mVideoEncoder->setConfig(&avcIntraPreriod);
    if(retStatus !=  ENCODE_SUCCESS) {
        LOGW("set avc intra period config failed");
    }

    mEncoderParams->intraPeriod = avcIntraPreriod.intraPeriod;
    mAVCParams->idrInterval = avcIntraPreriod.idrInterval;
    mAVCParams->ipPeriod = avcIntraPreriod.ipPeriod;
    return OMX_ErrorNone;
}

OMX_ERRORTYPE OMXVideoEncoderAVC::GetConfigVideoNalSize(OMX_PTR pStructure) {
    OMX_ERRORTYPE ret;
    OMX_VIDEO_CONFIG_NALSIZE *p = (OMX_VIDEO_CONFIG_NALSIZE *)pStructure;

    CHECK_TYPE_HEADER(p);
    CHECK_PORT_INDEX(p, OUTPORT_INDEX);
    memcpy(p, &mConfigNalSize, sizeof(*p));
    return OMX_ErrorNone;
}

OMX_ERRORTYPE OMXVideoEncoderAVC::SetConfigVideoNalSize(OMX_PTR pStructure) {
    OMX_ERRORTYPE ret;
    Encode_Status retStatus = ENCODE_SUCCESS;
    if (mParamIntelBitrate.eControlRate == OMX_Video_Intel_ControlRateMax) {
        LOGE("SetConfigVideoNalSize failed. Feature is disabled.");
        return OMX_ErrorUnsupportedIndex;
    }
    OMX_VIDEO_CONFIG_NALSIZE *p = (OMX_VIDEO_CONFIG_NALSIZE *)pStructure;
    CHECK_TYPE_HEADER(p);
    CHECK_PORT_INDEX(p, OUTPORT_INDEX);

    // set in either Loaded  state (ComponentSetParam) or Executing state (ComponentSetConfig)
    mConfigNalSize = *p;

    // return OMX_ErrorNone if not in Executing state
    // TODO: return OMX_ErrorIncorrectStateOperation?
    CHECK_SET_CONFIG_STATE();

    if (mParamIntelBitrate.eControlRate != OMX_Video_Intel_ControlRateVideoConferencingMode) {
        LOGE("SetConfigVideoNalSize failed. Feature is supported only in VCM.");
        return OMX_ErrorUnsupportedSetting;
    }
    VideoConfigNALSize configNalSize;
    configNalSize.maxSliceSize = mConfigNalSize.nNaluBytes * 8;
    retStatus = mVideoEncoder->setConfig(&configNalSize);
    if(retStatus != ENCODE_SUCCESS) {
        LOGW("set NAL size config failed");
    }
    return OMX_ErrorNone;
}

OMX_ERRORTYPE OMXVideoEncoderAVC::GetConfigIntelSliceNumbers(OMX_PTR pStructure) {
    OMX_ERRORTYPE ret;
    OMX_VIDEO_CONFIG_INTEL_SLICE_NUMBERS *p = (OMX_VIDEO_CONFIG_INTEL_SLICE_NUMBERS *)pStructure;

    CHECK_TYPE_HEADER(p);
    CHECK_PORT_INDEX(p, OUTPORT_INDEX);
    memcpy(p, &mConfigIntelSliceNumbers, sizeof(*p));
    return OMX_ErrorNone;
}

OMX_ERRORTYPE OMXVideoEncoderAVC::SetConfigIntelSliceNumbers(OMX_PTR pStructure) {
    OMX_ERRORTYPE ret;
    Encode_Status retStatus = ENCODE_SUCCESS;
    if (mParamIntelBitrate.eControlRate == OMX_Video_Intel_ControlRateMax) {
        LOGE("SetConfigIntelSliceNumbers failed. Feature is disabled.");
        return OMX_ErrorUnsupportedIndex;
    }
    OMX_VIDEO_CONFIG_INTEL_SLICE_NUMBERS *p = (OMX_VIDEO_CONFIG_INTEL_SLICE_NUMBERS *)pStructure;
    CHECK_TYPE_HEADER(p);
    CHECK_PORT_INDEX(p, OUTPORT_INDEX);

    // set in either Loaded  state (ComponentSetParam) or Executing state (ComponentSetConfig)
    mConfigIntelSliceNumbers = *p;

    // return OMX_ErrorNone if not in Executing state
    // TODO: return OMX_ErrorIncorrectStateOperation?
    CHECK_SET_CONFIG_STATE();

    if (mParamIntelBitrate.eControlRate != OMX_Video_Intel_ControlRateVideoConferencingMode) {
        LOGE("SetConfigIntelSliceNumbers failed. Feature is supported only in VCM.");
        return OMX_ErrorUnsupportedSetting;
    }
    VideoConfigSliceNum sliceNum;
    sliceNum.sliceNum.iSliceNum = mConfigIntelSliceNumbers.nISliceNumber;
    sliceNum.sliceNum.pSliceNum = mConfigIntelSliceNumbers.nPSliceNumber;
    retStatus = mVideoEncoder->setConfig(&sliceNum);
    if(retStatus != ENCODE_SUCCESS) {
        LOGW("set silce num config failed!\n");
    }
    return OMX_ErrorNone;
}

OMX_ERRORTYPE OMXVideoEncoderAVC::GetParamIntelAVCVUI(OMX_PTR pStructure) {

    OMX_ERRORTYPE ret;
    OMX_VIDEO_PARAM_INTEL_AVCVUI *p = (OMX_VIDEO_PARAM_INTEL_AVCVUI *)pStructure;

    CHECK_TYPE_HEADER(p);
    CHECK_PORT_INDEX(p, OUTPORT_INDEX);
    memcpy(p, &mParamIntelAvcVui, sizeof(*p));

    return OMX_ErrorNone;
}

OMX_ERRORTYPE OMXVideoEncoderAVC::SetParamIntelAVCVUI(OMX_PTR pStructure) {

    OMX_ERRORTYPE ret;
    OMX_VIDEO_PARAM_INTEL_AVCVUI *p = (OMX_VIDEO_PARAM_INTEL_AVCVUI *)pStructure;
    CHECK_TYPE_HEADER(p);
    CHECK_PORT_INDEX(p, OUTPORT_INDEX);

    // set only in Loaded state (ComponentSetParam)
    CHECK_SET_PARAM_STATE();

    mParamIntelAvcVui = *p;
    return OMX_ErrorNone;
}

OMX_ERRORTYPE OMXVideoEncoderAVC::GetParamVideoBytestream(OMX_PTR pStructure) {
    return OMX_ErrorUnsupportedSetting;
}

OMX_ERRORTYPE OMXVideoEncoderAVC::SetParamVideoBytestream(OMX_PTR pStructure) {
    OMX_ERRORTYPE ret;
    OMX_VIDEO_PARAM_BYTESTREAMTYPE *p = (OMX_VIDEO_PARAM_BYTESTREAMTYPE *)pStructure;
    CHECK_TYPE_HEADER(p);
    CHECK_PORT_INDEX(p, OUTPORT_INDEX);

    // set only in Loaded state (ComponentSetParam)
    CHECK_SET_PARAM_STATE();

    if (p->bBytestream == OMX_TRUE) {
        mNalStreamFormat.eNaluFormat = OMX_NaluFormatStartCodes;
    } else {
        // TODO: do we need to override the Nalu format?
        mNalStreamFormat.eNaluFormat = OMX_NaluFormatZeroByteInterleaveLength;
    }

    return OMX_ErrorNone;
}


DECLARE_OMX_COMPONENT("OMX.Intel.VideoEncoder.AVC", "video_encoder.avc", OMXVideoEncoderAVC);
