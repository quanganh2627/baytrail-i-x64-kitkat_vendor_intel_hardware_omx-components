/*
* Copyright (c) 2009-2012 Intel Corporation.  All rights reserved.
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


#define LOG_NDEBUG 1
#define LOG_TAG "OMXVideoDecoderAVCSecure"
#include <utils/Log.h>
#include "OMXVideoDecoderAVCSecure.h"
#include <time.h>
#include <signal.h>
#include <pthread.h>
#include <sys/ioctl.h>
#include <fcntl.h>

#include <math.h>
#include <cutils/properties.h>
#include <utils/String8.h>

extern "C" {
#include "widevine_me.h"
}
#define USE_SINGLE_SGL
#define PASS_FRAME_INFO 1
#define WV_CEILING(a,b) ((a)%(b)==0?(a):((a)/(b)+1)*(b))
#define DMA_BUFFER_SIZE (4 * 1024 * 1024)
// Be sure to have an equal string in VideoDecoderHost.cpp (libmix)
static const char* AVC_MIME_TYPE = "video/avc";
static const char* AVC_SECURE_MIME_TYPE = "video/avc-secure";

#define SEC_INITIAL_OFFSET      0 //1024
#define SEC_BUFFER_SIZE         (4 * 1024 * 1024)
#define KEEP_ALIVE_INTERVAL     5 // seconds
#define DRM_KEEP_ALIVE_TIMER    1000000
#define WV_SESSION_ID           0x00000011
#define NALU_BUFFER_SIZE        8192
#define FLUSH_WAIT_INTERVAL     (30 * 1000) //30 ms

// SEC addressable region
#define SEC_REGION_SIZE                 (0x01000000) // 16 MB
#define SEC_REGION_FRAME_BUFFERS_OFFSET (0)
#define SEC_REGION_FRAME_BUFFERS_SIZE   (0x00F00000) // 15 MB
#define SEC_REGION_NALU_BUFFERS_OFFSET  (SEC_REGION_FRAME_BUFFERS_OFFSET+SEC_REGION_FRAME_BUFFERS_SIZE)
#define SEC_REGION_NALU_BUFFERS_SIZE    (NALU_BUFFER_SIZE*INPORT_ACTUAL_BUFFER_COUNT)
#define SEC_REGION_PAVP_INFO_OFFSET     (SEC_REGION_NALU_BUFFERS_OFFSET+SEC_REGION_NALU_BUFFERS_SIZE)
#define SEC_REGION_PAVP_INFO_SIZE       (sizeof(pavp_info_t)*INPORT_ACTUAL_BUFFER_COUNT)

// FIXME: TEST ONLY, check and remove
static uint8_t* g_SECRegionTest_REMOVE_ME;

#pragma pack(push, 1)
#define WV_AES_IV_SIZE 16
typedef struct {
    uint16_t packet_byte_size; // number of bytes in this PES packet, same for input and output
    uint16_t packet_is_not_encrypted; // 1 if this PES packet is not encrypted.  0 otherwise
    uint8_t  packet_iv[WV_AES_IV_SIZE]; // IV used for CBC-CTS decryption, if the PES packet is encrypted
} wv_packet_metadata;
// TODO: synchronize SECFrameBuffer with SECDataBuffer in WVCrypto.cpp
// - offset replaced by index.


struct SECFrameBuffer {
    uint32_t index;
    uint32_t size;
    uint8_t  *data;
    uint8_t  clear;  // 0 when SEC offset is valid, 1 when data is valid
    uint8_t num_entries;
    wv_packet_metadata  packet_metadata[WV_MAX_PACKETS_IN_FRAME];
    uint8_t key[16];
    pavp_lib_session *pLibInstance;
    android::Mutex* pWVPAVPLock;
};


#pragma pack(pop)

uint8_t          outiv[WV_AES_IV_SIZE];
OMXVideoDecoderAVCSecure::OMXVideoDecoderAVCSecure()
    : mKeepAliveTimer(0),
      mSessionPaused(false),
      mpLibInstance(NULL),
	mSglbuffSet(false),
	mFrameCount(0),
      mDrmDevFd(-1) {
    mVideoDecoder = createVideoDecoder(AVC_SECURE_MIME_TYPE);
    if (!mVideoDecoder) {
        ALOGE("createVideoDecoder failed for \"%s\"", AVC_SECURE_MIME_TYPE);
    }
    // Override default native buffer count defined in the base class
    mNativeBufferCount = OUTPORT_NATIVE_BUFFER_COUNT;

    if (posix_memalign((void **)&mSglVideoBuffer.base, 8192, INPORT_BUFFER_SIZE) != 0) {
        ALOGE("Error in Allocating temp SGL Frame buffer");
        mSglVideoBuffer.base = NULL;
    }
    if (posix_memalign((void **)&mSglMetadataBuffer.base, 8192, 2*8192) != 0) {
        ALOGE("Error in Allocating temp SGL meta data buffer");
        free(mSglVideoBuffer.base);
        mSglVideoBuffer.base = NULL;
        mSglMetadataBuffer.base = NULL;
    }


    BuildHandlerList();
    mSECRegion.initialized = 0;
    mSessionReStart = false;
    mIFrame = false;
}

OMXVideoDecoderAVCSecure::~OMXVideoDecoderAVCSecure() {
    ALOGV("OMXVideoDecoderAVCSecure is destructed.");

    if (mDrmDevFd) {
        close(mDrmDevFd);
        mDrmDevFd = 0;
    }
    if(g_SECRegionTest_REMOVE_ME)
    {
        delete[] g_SECRegionTest_REMOVE_ME;
        g_SECRegionTest_REMOVE_ME = NULL;
    }
    free(mSglVideoBuffer.base);
    free(mSglMetadataBuffer.base);

    pavp_lib_session::pavp_lib_code rc = pavp_lib_session::status_ok;
    // Destroy the PAVP instance here instead of WVCrypto as there might be race condition while closing playback session
    rc = pavp_lib_session::pavp_lib_cleanup(mpLibInstance);

    ALOGE("OMXVideoDecoderAVCSecure is destructed.");
}

OMX_ERRORTYPE OMXVideoDecoderAVCSecure::InitInputPortFormatSpecific(OMX_PARAM_PORTDEFINITIONTYPE *paramPortDefinitionInput) {
    // OMX_PARAM_PORTDEFINITIONTYPE
    paramPortDefinitionInput->nBufferCountActual = INPORT_ACTUAL_BUFFER_COUNT;
    paramPortDefinitionInput->nBufferCountMin = INPORT_MIN_BUFFER_COUNT;
    paramPortDefinitionInput->nBufferSize = INPORT_BUFFER_SIZE;
    paramPortDefinitionInput->format.video.cMIMEType = (OMX_STRING)AVC_MIME_TYPE;
    paramPortDefinitionInput->format.video.eCompressionFormat = OMX_VIDEO_CodingAVC;

    // OMX_VIDEO_PARAM_AVCTYPE
    memset(&mParamAvc, 0, sizeof(mParamAvc));
    SetTypeHeader(&mParamAvc, sizeof(mParamAvc));
    mParamAvc.nPortIndex = INPORT_INDEX;
    // TODO: check eProfile/eLevel
    mParamAvc.eProfile = OMX_VIDEO_AVCProfileHigh; //OMX_VIDEO_AVCProfileBaseline;
    mParamAvc.eLevel = OMX_VIDEO_AVCLevel41; //OMX_VIDEO_AVCLevel1;

    // PREPRODUCTION: allocate 16MB region off the heap
    g_SECRegionTest_REMOVE_ME = new uint8_t[SEC_REGION_SIZE];
    if(!g_SECRegionTest_REMOVE_ME) {
        return OMX_ErrorInsufficientResources;
    }

    // Set up SEC-addressable memory region
    InitSECRegion(g_SECRegionTest_REMOVE_ME, SEC_REGION_SIZE);

    // Set memory allocator
    this->ports[INPORT_INDEX]->SetMemAllocator(MemAllocSEC, MemFreeSEC, this);

    return OMX_ErrorNone;
}

OMX_ERRORTYPE OMXVideoDecoderAVCSecure::ProcessorInit(void) {
    // Initialize "SEC" parser (omxsecpoc)
    int retval = parser_init();
    if(retval) {
        ALOGE("parser_init returned error %d", retval);
    }
    mSessionPaused = false;
    return OMXVideoDecoderBase::ProcessorInit();
}

OMX_ERRORTYPE OMXVideoDecoderAVCSecure::ProcessorDeinit(void) {
    // Session should be torn down in ProcessorStop, delayed to ProcessorDeinit
    // to allow remaining frames completely rendered.

    return OMXVideoDecoderBase::ProcessorDeinit();
}

OMX_ERRORTYPE OMXVideoDecoderAVCSecure::ProcessorStart(void) {
    uint32_t secOffset = 0;
    uint32_t secBufferSize = SEC_BUFFER_SIZE;
    uint32_t sessionID;

    mSessionPaused = false;
    return OMXVideoDecoderBase::ProcessorStart();
}

OMX_ERRORTYPE OMXVideoDecoderAVCSecure::ProcessorStop(void) {
    if (mKeepAliveTimer != 0) {
        timer_delete(mKeepAliveTimer);
        mKeepAliveTimer = 0;
    }

    ComponentCleanup();

    return OMXVideoDecoderBase::ProcessorStop();
}

OMX_ERRORTYPE OMXVideoDecoderAVCSecure::ComponentCleanup() {
    // destroy PAVP session
    bool bIsAlive = false;

    if(!mpLibInstance)
    {
        //Free frame and metadata buffers
        for(int i = 0; i < INPORT_ACTUAL_BUFFER_COUNT; i++) {
            ALOGD("OMXVideoDecoderAVCSecure Free frame and metadata buffers for index:%d\n", i);
            if (mSECRegion.frameBuffers.buffers[i].base)
                free(mSECRegion.frameBuffers.buffers[i].base);
            if (mSECRegion.naluBuffers.buffers[i].base)
                free(mSECRegion.naluBuffers.buffers[i].base);
	    if (mSECRegion.pavpInfo.buffers[i].base)
	        free(mSECRegion.pavpInfo.buffers[i].base);
        }
        return OMX_ErrorNone;
    }

    ALOGD("Finishing WV session");

    pavp_lib_session::pavp_lib_code rc = pavp_lib_session::status_ok;
    wv_set_xcript_key_in input;
    wv_set_xcript_key_out output;

    input.Header.ApiVersion = WV_API_VERSION;
    input.Header.CommandId =  wv_title_completed;
    input.Header.Status = 0;
    input.Header.BufferLength = sizeof(input)-sizeof(PAVP_CMD_HEADER);

    ALOGD("****** wv_title_completed: cmd_id: %x ******\n", wv_title_completed);

    if (mpLibInstance) {
        rc = mpLibInstance->sec_pass_through(
                reinterpret_cast<BYTE*>(&input),
                sizeof(input),
                reinterpret_cast<BYTE*>(&output),
                16);
    }

    if (rc != pavp_lib_session::status_ok)
    {
        ALOGE("sec_pass_through:wv_wv_title_completed() failed with error 0x%x\n", rc);
    } else {
        ALOGD("sec_pass_through: wv_title_completed() returned 0x%x\n", rc);
    }

    if (output.Header.Status)
    {
        ALOGD("SEC failed: wv_title_completed() returned 0x%x\n", output.Header.Status);
    } else {
        ALOGD("SEC passed: wv_title_completed()  returned 0x%x\n", output.Header.Status);
    }

    ALOGD("cleaning up sgl handles");

#ifdef USE_SINGLE_SGL

    rc = mpLibInstance->oem_crypto_uninit_dma(
                &mSglVideoBuffer.sglhandle);
    rc = mpLibInstance->oem_crypto_uninit_dma(
                &mSglMetadataBuffer.sglhandle);
#endif
    //Free frame and metadata buffers
    for(int i = 0; i < INPORT_ACTUAL_BUFFER_COUNT; i++) {
#ifndef USE_SINGLE_SGL
        rc = mpLibInstance->oem_crypto_uninit_dma(
                &mSECRegion.frameBuffers.buffers[i].sglhandle);
        if (rc != pavp_lib_session::status_ok)
            ALOGE("oem_crypto_uninit_dma mSECRegion.frameBuffers.buffers[%d] failed with error 0x%x\n", i,rc);
        else
            ALOGD("oem_crypto_uninit_dma mSECRegion.frameBuffers.buffers[%d] SUCCESS with error 0x%x\n", i,rc);

        rc = mpLibInstance->oem_crypto_uninit_dma(
                &mSECRegion.naluBuffers.buffers[i].sglhandle);
        if (rc != pavp_lib_session::status_ok)
            ALOGE("oem_crypto_uninit_dma mSECRegion.naluBuffers.buffers[%d] failed with error 0x%x\n", i,rc);
        else
            ALOGD("oem_crypto_uninit_dma mSECRegion.naluBuffers.buffers[%d] SUCCESS with error 0x%x\n", i,rc);

        ALOGD("OMXVideoDecoderAVCSecure free frame and metadata buffers for index:%d\n", i);
#endif
        if (mSECRegion.frameBuffers.buffers[i].base)
            free(mSECRegion.frameBuffers.buffers[i].base);
        if (mSECRegion.naluBuffers.buffers[i].base)
            free(mSECRegion.naluBuffers.buffers[i].base);
	if (mSECRegion.pavpInfo.buffers[i].base)
	    free(mSECRegion.pavpInfo.buffers[i].base);
    }//end of for

    //Check if session has been created already
    rc = pavp_lib_session::status_ok;
    ALOGD("Is there a active PAVP session ?\n");
    rc = mpLibInstance->pavp_is_session_alive(&bIsAlive);
    if (rc != pavp_lib_session::status_ok)
    ALOGE("pavp_destroy_session failed with error 0x%x\n", rc);
    ALOGE("PAVP session is %s", bIsAlive?"active":"in-active");

    //Destroy active session
    if(bIsAlive) {
        pavp_lib_session::pavp_lib_code rc = pavp_lib_session::status_ok;
        ALOGE("Destroying the PAVP session...\n");
        rc = mpLibInstance->pavp_destroy_session();
        if (rc != pavp_lib_session::status_ok)
            ALOGE("pavp_destroy_session failed with error 0x%x\n", rc);
    }

    return OMX_ErrorNone;
}


OMX_ERRORTYPE OMXVideoDecoderAVCSecure::ProcessorFlush(OMX_U32 portIndex) {
    return OMXVideoDecoderBase::ProcessorFlush(portIndex);
}

OMX_ERRORTYPE OMXVideoDecoderAVCSecure::ProcessorProcess(
        OMX_BUFFERHEADERTYPE ***pBuffers,
        buffer_retain_t *retains,
        OMX_U32 numberBuffers) {

    OMX_BUFFERHEADERTYPE *pInput = *pBuffers[INPORT_INDEX];
    SECFrameBuffer *secBuffer = (SECFrameBuffer *)pInput->pBuffer;
    if (pInput->nFilledLen == 0) {
        // error occurs during decryption.
        ALOGD("size of returned SEC buffer is 0, decryption fails.");
        mVideoDecoder->flush();
        usleep(FLUSH_WAIT_INTERVAL);
        OMX_BUFFERHEADERTYPE *pOutput = *pBuffers[OUTPORT_INDEX];
        pOutput->nFilledLen = 0;
        // reset SEC buffer size
        secBuffer->size = INPORT_BUFFER_SIZE;
        //Dont flush the ports if the decryption of a packet fails.
        //This leads to missing valid frames already queued leading to
        //artifacts in the video playback
        //this->ports[INPORT_INDEX]->FlushPort();
        //this->ports[OUTPORT_INDEX]->FlushPort();
        return OMX_ErrorNone;
    }

    OMX_ERRORTYPE ret;
    ret = OMXVideoDecoderBase::ProcessorProcess(pBuffers, retains, numberBuffers);
    if (ret != OMX_ErrorNone) {
        ALOGE("OMXVideoDecoderBase::ProcessorProcess failed. Result: %#x", ret);
        return ret;
    }
    if(mSessionReStart && !mIFrame) {
        retains[OUTPORT_INDEX] = BUFFER_RETAIN_NOT_RETAIN;
        OMX_BUFFERHEADERTYPE *pOutput = *pBuffers[OUTPORT_INDEX];
        pOutput->nFilledLen = 0;
        ALOGI("Dropped Frame\n");
        return OMX_ErrorNone;
    } else if(mSessionReStart && mIFrame) {
        mSessionReStart = false;
        mIFrame = false;
    }

    if (mSessionPaused && (retains[OUTPORT_INDEX] == BUFFER_RETAIN_GETAGAIN)) {
        retains[OUTPORT_INDEX] = BUFFER_RETAIN_NOT_RETAIN;
        OMX_BUFFERHEADERTYPE *pOutput = *pBuffers[OUTPORT_INDEX];
        pOutput->nFilledLen = 0;
        this->ports[INPORT_INDEX]->FlushPort();
        this->ports[OUTPORT_INDEX]->FlushPort();
    }

    return ret;
}

OMX_ERRORTYPE OMXVideoDecoderAVCSecure::ProcessorPause(void) {
    return OMXVideoDecoderBase::ProcessorPause();
}

OMX_ERRORTYPE OMXVideoDecoderAVCSecure::ProcessorResume(void) {
    return OMXVideoDecoderBase::ProcessorResume();
}

OMX_ERRORTYPE OMXVideoDecoderAVCSecure::PrepareConfigBuffer(VideoConfigBuffer *p) {
    OMX_ERRORTYPE ret;
    ret = OMXVideoDecoderBase::PrepareConfigBuffer(p);
    CHECK_RETURN_VALUE("OMXVideoDecoderBase::PrepareConfigBuffer");
    p->flag |=  WANT_SURFACE_PROTECTION;
    return ret;
}


int frame_file_count = 0;
int dumpframe(uint8_t *ptr, size_t size)
{
		char fname[128];
        FILE * fp = NULL;
		strcpy(fname, "/sdcard/frame_full");

        if( NULL == ptr || size <= 0 )
        {
				ALOGE("invalid argument");
                return (-1);
        }

		ALOGE("opening file %s",fname);

		if(!frame_file_count)
			fp = fopen(fname, "wb");
		else
			fp = fopen(fname, "ab");

        if( NULL == fp )
        {
				ALOGE("coulnt open file %s",fname);
                return (-1);
        }
        fwrite(ptr, size, 1, fp);
        fclose(fp);
	ALOGE("written frame%d to file %s",frame_file_count,fname);
        fp = NULL;
        frame_file_count++;
        return 0;
}


static int frame_count=0;
OMX_ERRORTYPE OMXVideoDecoderAVCSecure::PrepareDecodeBuffer(OMX_BUFFERHEADERTYPE *buffer, buffer_retain_t *retain, VideoDecodeBuffer *p) {
    OMX_ERRORTYPE ret;
    ALOGD("Entering OMXVideoDecoderAVCSecure::PrepareDecodeBuffer");
    //Default buffer status is Clear
    bool bClearBuff = 1;
    ret = OMXVideoDecoderBase::PrepareDecodeBuffer(buffer, retain, p);
    CHECK_RETURN_VALUE("OMXVideoDecoderBase::PrepareDecodeBuffer");
    ALOGV("Calling %s", __func__);
    if (buffer->nFilledLen == 0) {
        return OMX_ErrorNone;
    }
    // OMX_BUFFERFLAG_CODECCONFIG is an optional flag
    // if flag is set, buffer will only contain codec data.
    if (buffer->nFlags & OMX_BUFFERFLAG_CODECCONFIG) {
        ALOGV("Received AVC codec data.");
        return ret;
    }
    p->flag |= HAS_COMPLETE_FRAME;

    if (buffer->nOffset != 0) {
        ALOGV("buffer offset %d is not zero!!!", buffer->nOffset);
    }

	SECFrameBuffer *secBuffer = (SECFrameBuffer *)buffer->pBuffer;
	ALOGV("PrepareDecodeBuffer buffer = %p, index=%d",buffer,secBuffer->index);

	//Set DMA buffers here

	pavp_lib_session::pavp_lib_code rc = pavp_lib_session::status_ok;
	wv_sgl_entry sgl_entry[1];

	if(mSglbuffSet == false) {

		if(!mpLibInstance && secBuffer->pLibInstance) {

			uint8_t* addr;
			uint32_t temp;
			int counter=0;
#ifdef USE_SINGLE_SGL
                        mSglVideoBuffer.size = 1280*1024;
                        rc = secBuffer->pLibInstance->oem_crypto_init_dma( (uint8_t*)mSglVideoBuffer.base,
                                                                mSglVideoBuffer.size,
                                                                &mSglVideoBuffer.sglhandle);
                        ALOGD("oem_crypto_init_dma: got sglhandle %d for frame buffer 0x%x size=%d",
                                                                mSglVideoBuffer.sglhandle,
                                                                mSglVideoBuffer.base,
                                                                mSglVideoBuffer.size);
                        mSglMetadataBuffer.size = 8192;
                        rc = secBuffer->pLibInstance->oem_crypto_init_dma( (uint8_t*)mSglMetadataBuffer.base ,
                                                                mSglMetadataBuffer.size,
                                                                &mSglMetadataBuffer.sglhandle);
                        ALOGD("oem_crypto_init_dma: got sglhandle %d for metadata buffer 0x%x size=%d",
                                                                mSglMetadataBuffer.sglhandle,
                                                                mSglMetadataBuffer.base,
                                                                mSglMetadataBuffer.size);

#else
			for(int i = 0; i < INPORT_ACTUAL_BUFFER_COUNT; i++) {

				mSECRegion.frameBuffers.buffers[i].allocated = 0;
				//FIXME: need to change FW with 22 buffer support, hard code right now to 1280
				mSECRegion.frameBuffers.buffers[i].size = 1280*1024;//INPORT_BUFFER_SIZE;

				rc = secBuffer->pLibInstance->oem_crypto_init_dma( (uint8_t*)mSECRegion.frameBuffers.buffers[i].base ,
								mSECRegion.frameBuffers.buffers[i].size,
								&mSECRegion.frameBuffers.buffers[i].sglhandle);
				ALOGD("oem_crypto_init_dma: got sglhandle %d for frame buffer 0x%x size=%d",
								mSECRegion.frameBuffers.buffers[i].sglhandle,
								mSECRegion.frameBuffers.buffers[i].base,
								mSECRegion.frameBuffers.buffers[i].size);

				ALOGE("mSECRegion.frameBuffers.buffers[i].sglhandle = %x",mSECRegion.frameBuffers.buffers[i].sglhandle);

				mSECRegion.naluBuffers.buffers[i].allocated = 0;
				mSECRegion.naluBuffers.buffers[i].size = 8192;//NALU_BUFFER_SIZE;

				rc = secBuffer->pLibInstance->oem_crypto_init_dma( (uint8_t*)mSECRegion.naluBuffers.buffers[i].base ,
								mSECRegion.naluBuffers.buffers[i].size,
								&mSECRegion.naluBuffers.buffers[i].sglhandle);
				ALOGD("oem_crypto_init_dma: got sglhandle %d for nalu buffer 0x%x",mSECRegion.naluBuffers.buffers[i].sglhandle,mSECRegion.naluBuffers.buffers[i].base);
				ALOGE("mSECRegion.naluBuffer.buffers[i].sglhandle = %x",mSECRegion.naluBuffers.buffers[i].sglhandle);
			}//end of for
#endif
			mSglbuffSet = true;

		}//end of if(!mpLibInstance && secBuffer->pLibInstance)
	}//end of if(mSglbuffSet == false)

	uint32_t parse_size = 0;


	ALOGV("secBuffer->pLibInstance: %p", secBuffer->pLibInstance);
	if(!mpLibInstance && secBuffer->pLibInstance)
	{
		pavp_lib_session::pavp_lib_code rc = pavp_lib_session::status_ok;

		// Test Heavy mode session creation.
		ALOGD("PAVP Heavy: testing creation of a PAVP heavy session...\n");
		rc = secBuffer->pLibInstance->pavp_create_session(true);
		if (rc != pavp_lib_session::status_ok) {
			ALOGE("PAVP Heavy: pavp_create_session failed with error 0x%x\n", rc);
			ComponentCleanup();
			return OMX_ErrorHardware;
		} else {
                        mSessionReStart = true;
			ALOGD("PAVP Heavy: pavp_create_session SUCCESS: 0x%x\n", rc);
			mpLibInstance = secBuffer->pLibInstance;
			mLock =  secBuffer->pWVPAVPLock;
		}

		mpLibInstance = secBuffer->pLibInstance;
		{
			pavp_lib_session::pavp_lib_code rc = pavp_lib_session::status_ok;
			wv_set_xcript_key_in input;
			wv_set_xcript_key_out output;

			input.Header.ApiVersion = WV_API_VERSION;
			input.Header.CommandId =  wv_set_xcript_key;
			input.Header.Status = 0;
			input.Header.BufferLength = sizeof(input)-sizeof(PAVP_CMD_HEADER);


			ALOGD("****** wv_set_xcript_key1: cmd_id: %x ******\n", wv_set_xcript_key);

			if (secBuffer->pLibInstance) {
				rc = secBuffer->pLibInstance->sec_pass_through(
						reinterpret_cast<BYTE*>(&input),
						sizeof(input),
						reinterpret_cast<BYTE*>(&output),
						16);
			}

			if (rc != pavp_lib_session::status_ok)
			{
				ALOGE("sec_pass_through:wv_set_xcript_key() failed with error 0x%x\n", rc);
				ComponentCleanup();
				return OMX_ErrorHardware;
			}
			ALOGV("sec_pass_through: wv_set_xcript_key() returned 0x%x\n", rc);
			if (output.Header.Status)
				ALOGE("SEC failed: wv_set_xcript_key() returned 0x%x\n", output.Header.Status);
		}
	} else {
		mLock =  secBuffer->pWVPAVPLock;
	}



	ALOGV("mFrameCount %d",mFrameCount);

	if (mFrameCount == 0)
	{
		bool bCSHeartBeatStatus = 0;
		android::Mutex::Autolock autoLock(*mLock);
#if 1
                if (secBuffer->pLibInstance) {
		    rc = secBuffer->pLibInstance->check_connection_status_heart_beat(&bCSHeartBeatStatus);
                }
#endif
		ALOGV("mFrameCount %d check_connection_status_heart_beat bCSHeartBeatStatus %d",mFrameCount,bCSHeartBeatStatus);
		mFrameCount = 0;
		bool bIsAlive;

		if (rc != pavp_lib_session::status_ok) {
			ALOGE("check_connection_status_heart_beat failed 0x%x with status %d\n", rc,bCSHeartBeatStatus);
			if (mpLibInstance != NULL) {
				//Check if session has been created already
				rc = pavp_lib_session::status_ok;
				ALOGV("Is there a active PAVP session ?\n");
				rc = mpLibInstance->pavp_is_session_alive(&bIsAlive);
				if (rc != pavp_lib_session::status_ok)
					ALOGE("pavp_is_session_alive failed with error 0x%x\n", rc);
				ALOGV("PAVP session is %s", bIsAlive?"active":"in-active");


#ifdef USE_SINGLE_SGL
                                rc = secBuffer->pLibInstance->oem_crypto_uninit_dma(&mSglVideoBuffer.sglhandle);
                                if (rc != pavp_lib_session::status_ok)
                                    ALOGE("oem_crypto_uninit_dma frameBuffers handle=%dfailed with error 0x%x\n",mSglVideoBuffer.sglhandle,rc);

                                ALOGD("oem_crypto_uninit_dma: for handle %d for frame buffer 0x%x size=%d",
                                                                mSglVideoBuffer.sglhandle,
                                                                mSglVideoBuffer.base,
                                                                mSglVideoBuffer.size);
                                rc = secBuffer->pLibInstance->oem_crypto_uninit_dma(&mSglMetadataBuffer.sglhandle);
                                if (rc != pavp_lib_session::status_ok)
                                    ALOGE("oem_crypto_uninit_dma metadata handle=%dfailed with error 0x%x\n",&mSglMetadataBuffer.sglhandle,rc);
                                ALOGD("oem_crypto_uninit_dma: for handle %d for metadata buffer 0x%x size=%d",
                                                                mSglMetadataBuffer.sglhandle,
                                                                mSglMetadataBuffer.base,
                                                                mSglMetadataBuffer.size);

#else
				//Release frame and metadata handles
				for(int i = 0; i < INPORT_ACTUAL_BUFFER_COUNT; i++) {
					rc = mpLibInstance->oem_crypto_uninit_dma(
							&mSECRegion.frameBuffers.buffers[i].sglhandle);
					if (rc != pavp_lib_session::status_ok)
						ALOGE("oem_crypto_uninit_dma mSECRegion.frameBuffers.buffers[%d] failed with error 0x%x\n", i,rc);
					else
						ALOGV("oem_crypto_uninit_dma mSECRegion.frameBuffers.buffers[%d] SUCCESS with return 0x%x\n", i,rc);

					rc = mpLibInstance->oem_crypto_uninit_dma(
							&mSECRegion.naluBuffers.buffers[i].sglhandle);
					if (rc != pavp_lib_session::status_ok)
						ALOGE("oem_crypto_uninit_dma mSECRegion.naluBuffers.buffers[%d] failed with error 0x%x\n", i,rc);
					else
						ALOGV("oem_crypto_uninit_dma mSECRegion.naluBuffers.buffers[%d] SUCCESS with return 0x%x\n", i,rc);

					ALOGV("OMXVideoDecoderAVCSecure free frame and metadata buffers for index:%d\n", i);
				}//end of for
#endif
				//Destroy the PAVP session
				pavp_lib_session::pavp_lib_code rc = pavp_lib_session::status_ok;
				ALOGD("Destroying the PAVP session...\n");
				rc = mpLibInstance->pavp_destroy_session();
				if (rc != pavp_lib_session::status_ok)
					ALOGE("pavp_destroy_session failed with error 0x%x\n", rc);
				else
					ALOGV("pavp_destroy_session success: 0x%x\n", rc);

                                mVideoDecoder->flush();

				//Create the PAVP session
				ALOGD("PAVP Heavy: testing creation of a PAVP heavy session...\n");
				rc = mpLibInstance->pavp_create_session(true);
				if (rc != pavp_lib_session::status_ok) {
					ALOGE("PAVP Heavy: pavp_create_session failed with error 0x%x\n", rc);
				} else {
                                        mSessionReStart = true;
					ALOGV("PAVP Heavy: pavp_create_session SUCCESS: 0x%x\n", rc);
				}


				//Check the heartbeat status
				rc = secBuffer->pLibInstance->check_connection_status_heart_beat(&bCSHeartBeatStatus);
				if (rc != pavp_lib_session::status_ok) {
					ALOGE("check_connection_status_heart_beat Retry failed 0x%x with status %d\n", rc,bCSHeartBeatStatus);
					ComponentCleanup();
					return OMX_ErrorHardware;
				} else {
					ALOGV("check_connection_status_heart_beat Retry ok 0x%x with status %d\n", rc,bCSHeartBeatStatus);
				}


#ifdef USE_SINGLE_SGL
                        mSglVideoBuffer.size = 1280*1024;
                        rc = secBuffer->pLibInstance->oem_crypto_init_dma( (uint8_t*)mSglVideoBuffer.base,
                                                                mSglVideoBuffer.size,
                                                                &mSglVideoBuffer.sglhandle);
                        ALOGD("oem_crypto_init_dma: got sglhandle %d for frame buffer 0x%x size=%d",
                                                                mSglVideoBuffer.sglhandle,
                                                                mSglVideoBuffer.base,
                                                                mSglVideoBuffer.size);
                        mSglMetadataBuffer.size = 8192;
                        rc = secBuffer->pLibInstance->oem_crypto_init_dma( (uint8_t*)mSglMetadataBuffer.base ,
                                                                mSglMetadataBuffer.size,
                                                                &mSglMetadataBuffer.sglhandle);
                        ALOGD("oem_crypto_init_dma: got sglhandle %d for metadata buffer 0x%x size=%d",
                                                                mSglMetadataBuffer.sglhandle,
                                                                mSglMetadataBuffer.base,
                                                                mSglMetadataBuffer.size);

#else

				//Allocate the sgl handles
				for(int i = 0; i < INPORT_ACTUAL_BUFFER_COUNT; i++) {

					mSECRegion.frameBuffers.buffers[i].allocated = 0;
					//FIXME: need to change FW with 22 buffer support, hard code right now to 1280
					mSECRegion.frameBuffers.buffers[i].size = 1280*1024;//INPORT_BUFFER_SIZE;

					rc = secBuffer->pLibInstance->oem_crypto_init_dma( (uint8_t*)mSECRegion.frameBuffers.buffers[i].base ,
							mSECRegion.frameBuffers.buffers[i].size,
							&mSECRegion.frameBuffers.buffers[i].sglhandle);
					ALOGD("oem_crypto_init_dma: got sglhandle %d for frame buffer 0x%x size=%d",
							mSECRegion.frameBuffers.buffers[i].sglhandle,
							mSECRegion.frameBuffers.buffers[i].base,
							mSECRegion.frameBuffers.buffers[i].size);

					ALOGD("mSECRegion.frameBuffers.buffers[i].sglhandle = %x",mSECRegion.frameBuffers.buffers[i].sglhandle);

					mSECRegion.naluBuffers.buffers[i].allocated = 0;
					mSECRegion.naluBuffers.buffers[i].size = 8192;//NALU_BUFFER_SIZE;

					rc = secBuffer->pLibInstance->oem_crypto_init_dma( (uint8_t*)mSECRegion.naluBuffers.buffers[i].base ,
							mSECRegion.naluBuffers.buffers[i].size,
							&mSECRegion.naluBuffers.buffers[i].sglhandle);
					ALOGD("oem_crypto_init_dma: got sglhandle %d for nalu buffer 0x%x",mSECRegion.naluBuffers.buffers[i].sglhandle,mSECRegion.naluBuffers.buffers[i].base);
					ALOGD("mSECRegion.naluBuffer.buffers[i].sglhandle = %x",mSECRegion.naluBuffers.buffers[i].sglhandle);
				}//end of for
#endif
				//Set the Xcript key
				{
					pavp_lib_session::pavp_lib_code rc = pavp_lib_session::status_ok;
					wv_set_xcript_key_in input;
					wv_set_xcript_key_out output;

					input.Header.ApiVersion = WV_API_VERSION;
					input.Header.CommandId =  wv_set_xcript_key;
					input.Header.Status = 0;
					input.Header.BufferLength = sizeof(input)-sizeof(PAVP_CMD_HEADER);

					ALOGD("****** wv_set_xcript_key1: cmd_id: %x ******\n", wv_set_xcript_key);

					rc = mpLibInstance->sec_pass_through(
							reinterpret_cast<BYTE*>(&input),
							sizeof(input),
							reinterpret_cast<BYTE*>(&output),
							16);

					if (rc != pavp_lib_session::status_ok)
					{
						ALOGE("sec_pass_through:wv_set_xcript_key() failed with error 0x%x\n", rc);
					    ComponentCleanup();
						return OMX_ErrorHardware;
					}
					ALOGV("sec_pass_through: wv_set_xcript_key() returned 0x%x\n", rc);
					if (output.Header.Status)
						ALOGE("SEC failed: wv_set_xcript_key() returned 0x%x\n", output.Header.Status);
				}

			} else {
				ALOGE("mpLibInstance is NULL!!!!! \n");
			}
		} else {
			ALOGV("check_connection_status_heart_beat ok 0x%x with status %d\n", rc,bCSHeartBeatStatus);
		}
	}

	if(++mFrameCount >= 100)
		mFrameCount = 0;


	{
		wv_heci_process_video_frame_in input;
		wv_heci_process_video_frame_out output;
		sec_wv_packet_metadata metadata;
                memset(&output,0,sizeof(wv_heci_process_video_frame_out));

		input.Header.ApiVersion = WV_API_VERSION;
		input.Header.CommandId = wv_process_video_frame;
		input.Header.Status = 0;
		input.Header.BufferLength = sizeof(input) - sizeof(PAVP_CMD_HEADER);

		input.num_of_packets = secBuffer->num_entries;
		input.is_frame_not_encrypted = secBuffer->clear;

		ALOGV("Input to SEC: %s", secBuffer->clear?"clear":"encrypted");
#ifdef USE_SINGLE_SGL
                input.frame_handle = mSglVideoBuffer.sglhandle;
                input.metadata_handle = mSglMetadataBuffer.sglhandle;
		input.parsed_header_handle =  mSglMetadataBuffer.sglhandle;
#else
		input.frame_handle =  mSECRegion.frameBuffers.buffers[secBuffer->index].sglhandle;
		input.metadata_handle =  mSECRegion.naluBuffers.buffers[secBuffer->index].sglhandle;
		input.parsed_header_handle =  mSECRegion.naluBuffers.buffers[secBuffer->index].sglhandle;
#endif

#ifndef USE_SINGLE_SGL
		//TEMP:FIXME doing memcpy to align right now
		ALOGV("copy to temp buffer secBuffer->data=%p temp_frame=%p nFilledlen=%d",secBuffer->data, temp_frame,buffer->nFilledLen);
		memcpy(mSglVideoBuffer.base, secBuffer->data, buffer->nFilledLen);
		ALOGV("copy to temp buffer done  sec buff size=%d",secBuffer->size);
#endif
		//FIXME: for hsw - check if required
		int align_offset = 0;
		//memset((secBuffer->data),0,secBuffer->size);
		for(int pes_count=0, pesoffset =0, dmaoffset=0; pes_count < secBuffer->num_entries; pes_count++) {

			ALOGV(" num_entries : %d\n", secBuffer->num_entries);
			ALOGV(" size: %d", secBuffer->packet_metadata[pes_count].packet_byte_size);
			ALOGV(" encrypted: %d", secBuffer->packet_metadata[pes_count].packet_is_not_encrypted);

			//Update Buffer status with PES Encryption flag
			if (bClearBuff) {
				bClearBuff = secBuffer->packet_metadata[pes_count].packet_is_not_encrypted;
			}

			ALOGV("PrepareDecoderBuffer: Copy meta data ");
			metadata.packet_byte_size = secBuffer->packet_metadata[pes_count].packet_byte_size;
			memset(&metadata.packet_iv[0], 0x0, sizeof(metadata.packet_iv));
#ifdef USE_SINGLE_SGL
                        memcpy((unsigned char *)mSglMetadataBuffer.base + (pes_count * sizeof(metadata)),(unsigned char*) &metadata, sizeof(metadata));
#else
			memcpy(mSECRegion.naluBuffers.buffers[secBuffer->index].base + (pes_count * sizeof(metadata)), &metadata, sizeof(metadata));
#endif

			//copy meta data
			ALOGV("PrepareDecoderBuffer: Copy frame data to aligned address pes_count=%d ", pes_count);
			//
			align_offset = WV_CEILING(align_offset,8192);
#ifdef USE_SINGLE_SGL
                        ALOGD("PrepareDecoderBuffer: Copy frame data to aligned address pes_count=%d align_offset=%x, Org_buff=%x, Dst = %x temp=%x Src=%x, size=%d",pes_count,align_offset,mSglVideoBuffer.base,mSglVideoBuffer.base+align_offset, secBuffer->data, secBuffer->data+pesoffset, metadata.packet_byte_size);

                        memcpy((unsigned char*)(mSglVideoBuffer.base+align_offset),(unsigned char*)(secBuffer->data +pesoffset),metadata.packet_byte_size);
#else
			memcpy((secBuffer->data+align_offset),(mSglVideoBuffer.base+pesoffset),metadata.packet_byte_size);
#endif

			//update offset
			pesoffset += metadata.packet_byte_size;
			align_offset += metadata.packet_byte_size;
		}
		ALOGV("Size after aligning size=%d  original size=%d",align_offset,secBuffer->size);
		secBuffer->size = align_offset;

		ALOGV("****** wv_process_video_frame: cmd_id: %x ******\n", wv_process_video_frame);
		ALOGV("wv_process_video_frame: frame_handle=%x meta_handle=%x index=%x buffclear=%d bClearBuff=%d",input.frame_handle, input.metadata_handle,secBuffer->index, input.is_frame_not_encrypted, bClearBuff);

		//Check if Buffer Status already set match PES packets
		//Even if one of the packets is encrypted we set buffer status to Encrypted
		if (input.is_frame_not_encrypted != bClearBuff) {
			secBuffer->clear = bClearBuff;
			input.is_frame_not_encrypted = bClearBuff;
			ALOGV("Update the buffer encryption status based on PES packet, Frame not encrypted is: %d\n", input.is_frame_not_encrypted);
		}

		if (secBuffer->pLibInstance) {

			android::Mutex::Autolock autoLock(*mLock);
			rc = secBuffer->pLibInstance->sec_pass_through(
			reinterpret_cast<BYTE*>(&input),
			sizeof(input),
			reinterpret_cast<BYTE*>(&output),
			sizeof(output));
		}

		if (rc != pavp_lib_session::status_ok) {
			ALOGE(" sec_pass_through failed with error 0x%x\n", rc);
			ComponentCleanup();
			return OMX_ErrorHardware;
		} else {
			ALOGV(" sec_pass_through passed 0x%x\n", rc);
		}
		if(output.Header.Status){
			ALOGV(" ME returned error for process video frame  0x%x\n", output.Header.Status);
			//For 0xf0033(WV_FAIL_CONNECTION_STATUS_CHECK_OVERDUE) means heart beat check is pending
			//hence handle it below
			if(output.Header.Status == WV_FAIL_CONNECTION_STATUS_CHECK_OVERDUE) {
				bool bCSHeartBeatStatus = 0;
				android::Mutex::Autolock autoLock(*mLock);
				if (secBuffer->pLibInstance) {
					rc = secBuffer->pLibInstance->check_connection_status_heart_beat(&bCSHeartBeatStatus);
				}

				if (rc != pavp_lib_session::status_ok) {
					ALOGE("check_connection_status_heart_beat failed on retry 0x%x with status %d\n", rc,bCSHeartBeatStatus);
					ALOGE("Stop the playback...%d\n");
					ComponentCleanup();
					return OMX_ErrorHardware;
				} else {
					mFrameCount = 0;
					ALOGV("check_connection_status_heart_beat ok on retry 0x%x with status %d\n", rc,bCSHeartBeatStatus);
                                        if(secBuffer->pLibInstance) {
					   rc = secBuffer->pLibInstance->sec_pass_through(
							   reinterpret_cast<BYTE*>(&input),
							   sizeof(input),
							   reinterpret_cast<BYTE*>(&output),
							   sizeof(output));

					   if (rc != pavp_lib_session::status_ok) {
						  ALOGE(" sec_pass_through failed on retry with error 0x%x\n", rc);
						  ComponentCleanup();
						  return OMX_ErrorHardware;
					   }
					   else
						ALOGV(" sec_pass_through passed on retry 0x%x\n", rc);
				        }
                                }
			}
			else {
				ALOGE(" ME returned fatal error for process video frame  0x%x, Stop playback...\n", output.Header.Status);
				ComponentCleanup();
				return OMX_ErrorHardware;
			}
		}
		else{
			ALOGV(" ME Success for video passed \n");
		}

		{
			ALOGV("  sec_pass_through:wv_process_video_frame() returned 0x%x\n", rc);
#ifdef USE_SINGLE_SGL
                        memcpy((unsigned char*)secBuffer->data, mSglVideoBuffer.base, buffer->nFilledLen);
#endif
			ALOGV("  parsed_data_size: %d", output.parsed_data_size);
			parse_size = output.parsed_data_size;
			ALOGV("PrepareDecodeBuffer:Copy full parsed data");
			ALOGV("memcpy size nfilledLne %d + output parsed size %d  to secBuffer->size %d",buffer->nFilledLen, output.parsed_data_size,secBuffer->size);

#ifdef USE_SINGLE_SGL
                        //FIXME: Check why is this required
                        memcpy((unsigned char *)(secBuffer->data + buffer->nFilledLen + 4), mSglMetadataBuffer.base, output.parsed_data_size);
#else
			memcpy((unsigned char *)(secBuffer->data + buffer->nFilledLen + 4), (const unsigned int*) (mSECRegion.naluBuffers.buffers[secBuffer->index].base ), output.parsed_data_size);
#endif
			ALOGV("PrepareDecodeBuffer:Copy out IV size %d",WV_AES_IV_SIZE);
			memset(&outiv, 0x0, WV_AES_IV_SIZE);
			memcpy(&outiv, output.iv, WV_AES_IV_SIZE);
		}
	}


	p->data = secBuffer->data + buffer->nOffset;
	p->size = buffer->nFilledLen;

	SECParsedFrame* parsedFrame = &(mParsedFrames[secBuffer->index]);
#ifdef USE_SINGLE_SGL
        memcpy(parsedFrame->nalu_data, mSglMetadataBuffer.base, parse_size);
#endif
	parsedFrame->nalu_data_size = parse_size;

	ALOGV("got parsedframe index %d pavpinfo addr %p", secBuffer->index, parsedFrame->pavp_info);

	if (parsedFrame->pavp_info) {
		parsedFrame->pavp_info->mode = 4;
		parsedFrame->pavp_info->app_id = 0;

		ALOGV("frame_count before copying: %d outiv: %x %x %x %x", frame_count,
				parsedFrame->pavp_info->iv[0],
				parsedFrame->pavp_info->iv[1],
				parsedFrame->pavp_info->iv[2],
				parsedFrame->pavp_info->iv[3]);
		memcpy(parsedFrame->pavp_info->iv, outiv, WV_AES_IV_SIZE);

		ALOGV("frame_count: %d outiv: %x %x %x %x", frame_count,
				parsedFrame->pavp_info->iv[0],
				parsedFrame->pavp_info->iv[1],
				parsedFrame->pavp_info->iv[2],
				parsedFrame->pavp_info->iv[3]);
	}
	{
		ret = ConstructFrameInfo(p->data, p->size, parsedFrame->pavp_info,
				parsedFrame->nalu_data, parsedFrame->nalu_data_size, &(parsedFrame->frame_info));
		ALOGV("ConstructFrameInfo done");
	}

	if (parsedFrame->frame_info.num_nalus == 0 ) {
		ALOGE("NALU parsing failed - num_nalus = 0!, Return Error OMX Not Ready!!!");
		secBuffer->size = 0;
		ret = OMX_ErrorNotReady;
	}

    if(ret == OMX_ErrorNone) {
#ifdef PASS_FRAME_INFO
      if(mSessionReStart && !mIFrame) {
          ALOGD("Skip non-I frame\n");
          p->data = (uint8_t *)&(parsedFrame->frame_info);
          p->size = sizeof(frame_info_t);
          ret = OMX_ErrorNotReady;
      } else {
        ALOGV("Pass frame info to VideoDecoderAVCSecure in VideoDecodeBuffer");
        p->data = (uint8_t *)&(parsedFrame->frame_info);
        p->size = sizeof(frame_info_t);
        p->flag = p->flag | IS_SECURE_DATA;
     }

#else
        // Pass decrypted frame
        ALOGV("Pass decrypted clear frame");
        p->data = secBuffer->data + buffer->nOffset;
        p->size = buffer->nFilledLen;
#endif
    }
    frame_count++;
    return ret;
}

OMX_COLOR_FORMATTYPE OMXVideoDecoderAVCSecure::GetOutputColorFormat(int width, int height) {
    // HWC expects Tiled output color format for all resolution
    return OMX_INTEL_COLOR_FormatYUV420PackedSemiPlanar_Tiled;
}

OMX_ERRORTYPE OMXVideoDecoderAVCSecure::BuildHandlerList(void) {
    OMXVideoDecoderBase::BuildHandlerList();
    AddHandler(OMX_IndexParamVideoAvc, GetParamVideoAvc, SetParamVideoAvc);
    AddHandler(OMX_IndexParamVideoProfileLevelQuerySupported, GetParamVideoAVCProfileLevel, SetParamVideoAVCProfileLevel);
    AddHandler(static_cast<OMX_INDEXTYPE> (OMX_IndexExtEnableNativeBuffer), GetNativeBufferMode, SetNativeBufferMode);
    return OMX_ErrorNone;
}

OMX_ERRORTYPE OMXVideoDecoderAVCSecure::GetParamVideoAvc(OMX_PTR pStructure) {
    OMX_ERRORTYPE ret;
    OMX_VIDEO_PARAM_AVCTYPE *p = (OMX_VIDEO_PARAM_AVCTYPE *)pStructure;
    CHECK_TYPE_HEADER(p);
    CHECK_PORT_INDEX(p, INPORT_INDEX);

    memcpy(p, &mParamAvc, sizeof(*p));
    return OMX_ErrorNone;
}

OMX_ERRORTYPE OMXVideoDecoderAVCSecure::SetParamVideoAvc(OMX_PTR pStructure) {
    OMX_ERRORTYPE ret;
    OMX_VIDEO_PARAM_AVCTYPE *p = (OMX_VIDEO_PARAM_AVCTYPE *)pStructure;
    CHECK_TYPE_HEADER(p);
    CHECK_PORT_INDEX(p, INPORT_INDEX);
    CHECK_SET_PARAM_STATE();

    // TODO: do we need to check if port is enabled?
    // TODO: see SetPortAvcParam implementation - Can we make simple copy????
    memcpy(&mParamAvc, p, sizeof(mParamAvc));
    return OMX_ErrorNone;
}


OMX_ERRORTYPE OMXVideoDecoderAVCSecure::GetParamVideoAVCProfileLevel(OMX_PTR pStructure) {
    OMX_ERRORTYPE ret;
    OMX_VIDEO_PARAM_PROFILELEVELTYPE *p = (OMX_VIDEO_PARAM_PROFILELEVELTYPE *)pStructure;
    CHECK_TYPE_HEADER(p);
    CHECK_PORT_INDEX(p, INPORT_INDEX);
    CHECK_ENUMERATION_RANGE(p->nProfileIndex,1);

    p->eProfile = mParamAvc.eProfile;
    p->eLevel = mParamAvc.eLevel;

    return OMX_ErrorNone;
}

OMX_ERRORTYPE OMXVideoDecoderAVCSecure::SetParamVideoAVCProfileLevel(OMX_PTR pStructure) {
    ALOGW("SetParamVideoAVCProfileLevel is not supported.");
    return OMX_ErrorUnsupportedSetting;
}

OMX_ERRORTYPE OMXVideoDecoderAVCSecure::GetNativeBufferMode(OMX_PTR pStructure) {
    LOGE("GetNativeBufferMode is not implemented");
    return OMX_ErrorNotImplemented;
}

OMX_ERRORTYPE OMXVideoDecoderAVCSecure::SetNativeBufferMode(OMX_PTR pStructure) {
    OMXVideoDecoderBase::SetNativeBufferMode(pStructure);
    PortVideo *port = NULL;
    port = static_cast<PortVideo *>(this->ports[OUTPORT_INDEX]);

    OMX_PARAM_PORTDEFINITIONTYPE port_def;
    memcpy(&port_def,port->GetPortDefinition(),sizeof(port_def));
    port_def.format.video.eColorFormat = OMX_INTEL_COLOR_FormatYUV420PackedSemiPlanar_Tiled;
    port->SetPortDefinition(&port_def,true);

    return OMX_ErrorNone;
}

OMX_U8* OMXVideoDecoderAVCSecure::MemAllocSEC(OMX_U32 nSizeBytes, OMX_PTR pUserData) {
    OMXVideoDecoderAVCSecure* p = (OMXVideoDecoderAVCSecure *)pUserData;
    if (p) {
        return p->MemAllocSEC(nSizeBytes);
    }
    ALOGE("NULL pUserData.");
    return NULL;
}

void OMXVideoDecoderAVCSecure::MemFreeSEC(OMX_U8 *pBuffer, OMX_PTR pUserData) {
    OMXVideoDecoderAVCSecure* p = (OMXVideoDecoderAVCSecure *)pUserData;
    if (p) {
        p->MemFreeSEC(pBuffer);
        return;
    }
    ALOGE("NULL pUserData.");
}

OMX_U8* OMXVideoDecoderAVCSecure::MemAllocSEC(OMX_U32 nSizeBytes) {
    if (nSizeBytes > INPORT_BUFFER_SIZE) {
        ALOGE("Invalid size (%lu) of memory to allocate.", nSizeBytes);
        return NULL;
    }
    //LOGW_IF(nSizeBytes != INPORT_BUFFER_SIZE, "WARNING:MemAllocSEC asked to allocate buffer of size %lu (expected %lu)", nSizeBytes, INPORT_BUFFER_SIZE);

    int index = 0;
    for (; index < INPORT_ACTUAL_BUFFER_COUNT; index++) {
        if(!mSECRegion.frameBuffers.buffers[index].allocated) {
        break;
	}
    }
    if(index >= INPORT_ACTUAL_BUFFER_COUNT) {
        ALOGE("No free buffers");
        return NULL;
    }

    SECFrameBuffer *pBuffer = new SECFrameBuffer;
    if (pBuffer == NULL) {
        ALOGE("Failed to allocate SECFrameBuffer.");
        return NULL;
    }

    pBuffer->index = index;
    pBuffer->data = mSECRegion.frameBuffers.buffers[index].base;
    pBuffer->size = mSECRegion.frameBuffers.buffers[index].size;
    mParsedFrames[index].nalu_data = mSECRegion.naluBuffers.buffers[index].base;
    mParsedFrames[index].nalu_data_size = mSECRegion.naluBuffers.buffers[index].size;
    mParsedFrames[index].pavp_info = (pavp_info_t*)mSECRegion.pavpInfo.buffers[index].base;
	ALOGE("allocaed mParsedFrames[index].pavp_info index %d adddr %p",index, (void*)mParsedFrames[index].pavp_info);
    mSECRegion.frameBuffers.buffers[index].allocated = 1;
    mSECRegion.naluBuffers.buffers[index].allocated = 1;
    mSECRegion.pavpInfo.buffers[index].allocated = 1;

    return (OMX_U8 *) pBuffer;
}

void OMXVideoDecoderAVCSecure::MemFreeSEC(OMX_U8 *pBuffer) {
    SECFrameBuffer *p = (SECFrameBuffer*) pBuffer;
    if (p == NULL) {
        return;
    }

    mSECRegion.frameBuffers.buffers[p->index].allocated = 0;
    mSECRegion.naluBuffers.buffers[p->index].allocated = 0;
    mSECRegion.pavpInfo.buffers[p->index].allocated = 0;

    delete(p);
}

OMX_ERRORTYPE OMXVideoDecoderAVCSecure::InitSECRegion(uint8_t* region, uint32_t size)
{
    if(mSECRegion.initialized) {
        return OMX_ErrorNone;
    }

    mSECRegion.base = region;
    mSECRegion.size = size;

    pavp_lib_session::pavp_lib_code rc = pavp_lib_session::status_ok;
    if (mSglVideoBuffer.base == NULL) {
        ALOGE("temp SGL frame buffer allocation had failed in constructor");
        return OMX_ErrorInsufficientResources;
    }
    if (mSglMetadataBuffer.base == NULL) {
       ALOGE("temp SGL metadata buffer allocation had failed in constructor");
       return OMX_ErrorInsufficientResources;
    }


    for(int i = 0; i < INPORT_ACTUAL_BUFFER_COUNT; i++) {

        void* addr = NULL;

       //Frame buffer allocation
        if (posix_memalign(&addr,8192,INPORT_BUFFER_SIZE) == 0) {
            mSECRegion.frameBuffers.buffers[i].allocated = 0;
            mSECRegion.frameBuffers.buffers[i].base = (uint8_t*)addr;
            mSECRegion.frameBuffers.buffers[i].size = INPORT_BUFFER_SIZE;
        } else {
            mSECRegion.frameBuffers.buffers[i].base = NULL;
            ComponentCleanup();
            return OMX_ErrorInsufficientResources;
        }

        //FIXME: NALU right now hard coded to 8K(2 pages)
        if (posix_memalign(&addr,8192,2*8192) == 0) {
            mSECRegion.naluBuffers.buffers[i].allocated = 0;
            mSECRegion.naluBuffers.buffers[i].base = (uint8_t*)addr;
            mSECRegion.naluBuffers.buffers[i].size = NALU_BUFFER_SIZE;
        } else {
            mSECRegion.naluBuffers.buffers[i].base = NULL;
            ComponentCleanup();
            return OMX_ErrorInsufficientResources;
        }


	if (posix_memalign(&addr,8192,sizeof(pavp_info_t) + (2*8192)) == 0) {
		mSECRegion.pavpInfo.buffers[i].allocated = 0;
		mSECRegion.pavpInfo.buffers[i].base = (uint8_t*)addr;
		mSECRegion.pavpInfo.buffers[i].size = sizeof(pavp_info_t);
	} else {
            mSECRegion.pavpInfo.buffers[i].base = NULL;
            ComponentCleanup();
            return OMX_ErrorInsufficientResources;
        }

        ALOGD("allocating PAVP_info for %d size %d bytes ptr %p", i,(sizeof(pavp_info_t) + (2*4096)),mSECRegion.pavpInfo.buffers[i].base );
    }
    mSECRegion.initialized = 1;

    return OMX_ErrorNone;
}

OMX_ERRORTYPE OMXVideoDecoderAVCSecure::ConstructFrameInfo(
    uint8_t* frame_data,
    uint32_t frame_size,
    pavp_info_t* pavp_info,
    uint8_t* nalu_data,
    uint32_t nalu_data_size,
    frame_info_t* frame_info) {

    uint32_t* dword_ptr = (uint32_t*)nalu_data;
    uint8_t* byte_ptr = NULL;
    uint32_t data_size = 0;
    bool Iflag = false;

    frame_info->data = frame_data;
    frame_info->length = frame_size;
    frame_info->pavp = pavp_info;

#if BYT_SW_PARSE
	frame_info->num_nalus = byteswap_32(*dword_ptr);
#else
	frame_info->num_nalus = (*dword_ptr);
#endif

    dword_ptr++;
    ALOGV("frame_info->num_nalus = %d %x", frame_info->num_nalus, frame_info->num_nalus);
    for(uint32_t n = 0; n < frame_info->num_nalus; n++) {
        // Byteswap offset
        ALOGV("NaluIdx = %d", n);
#if BYT_SW_PARSE
		frame_info->nalus[n].offset = byteswap_32(*dword_ptr);
#else
        frame_info->nalus[n].offset = (*dword_ptr);
#endif

        dword_ptr++;
        ALOGV("offset = %d %x", frame_info->nalus[n].offset, frame_info->nalus[n].offset);
#if BYT_SW_PARSE
       // Byteswap nalu_size
	   frame_info->nalus[n].length = byteswap_32(*dword_ptr);
#else
       frame_info->nalus[n].length = (*dword_ptr);
#endif

        dword_ptr++;
        ALOGV("length = %d  %x", frame_info->nalus[n].length, frame_info->nalus[n].length);

#if BYT_SW_PARSE
        // Byteswap data_size
        data_size = byteswap_32(*dword_ptr);
#else
		data_size = (*dword_ptr);
#endif
        dword_ptr++;
        ALOGV("data_size = %d %x", data_size, data_size);

        byte_ptr = (uint8_t*)dword_ptr;
        frame_info->nalus[n].type = *byte_ptr;
        switch(frame_info->nalus[n].type & 0x1F) {
        ALOGV("nalutype = 0x%x", frame_info->nalus[n].type & 0x1F);
        case h264_NAL_UNIT_TYPE_SPS:
        case h264_NAL_UNIT_TYPE_PPS:
        case h264_NAL_UNIT_TYPE_SEI:
            // Point to cleartext in nalu data buffer
            frame_info->nalus[n].data = byte_ptr;
            frame_info->nalus[n].slice_header = NULL;
            break;
        case h264_NAL_UNIT_TYPE_SLICE:
        case h264_NAL_UNIT_TYPE_IDR:

            if((frame_info->nalus[n].type & 0x1F) == h264_NAL_UNIT_TYPE_IDR)
              Iflag = true;

            // Point to ciphertext in frame buffer
            frame_info->nalus[n].data = frame_info->data + frame_info->nalus[n].offset;
#if BYT_SW_PARSE
            //FIXME: commenting byteswap., check if required
			byteswap_slice_header((slice_header_t*)byte_ptr);
#endif
            frame_info->nalus[n].slice_header = (slice_header_t*)byte_ptr;

            ALOGV("pps_id = %d",frame_info->nalus[n].slice_header->pps_id);
            ALOGV("frame_num = %d",frame_info->nalus[n].slice_header->frame_num);
            frame_info->dec_ref_pic_marking = NULL;
            if(data_size > sizeof(slice_header_t)) {
                ALOGV("frame_info->dec_ref_pic_marking = %p", frame_info->dec_ref_pic_marking);
                byte_ptr += sizeof(slice_header_t);
                frame_info->dec_ref_pic_marking = (dec_ref_pic_marking_t*)byte_ptr;
            }
            ALOGV("pps_id = %d",frame_info->nalus[n].slice_header->pps_id);
            ALOGV("frame_num = %d",frame_info->nalus[n].slice_header->frame_num);
            break;
        default:
            ALOGE("ERROR: SEC returned an unsupported NALU type: %x", frame_info->nalus[n].type);
            frame_info->nalus[n].data = NULL;
            frame_info->nalus[n].slice_header = NULL;
            break;
        }
        ALOGV("frame_info->nalus[n].data = 0x%x", frame_info->nalus[n].data);

        // Advance to next NALU (including padding)
        dword_ptr += (data_size + 3) >> 2;
    }
    if(Iflag)
       mIFrame = true;
    else
       mIFrame = false;

    return OMX_ErrorNone;
}

DECLARE_OMX_COMPONENT("OMX.Intel.hw_vd.h264.secure", "video_decoder.avc", OMXVideoDecoderAVCSecure);
