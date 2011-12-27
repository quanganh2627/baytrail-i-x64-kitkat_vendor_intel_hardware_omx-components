/*
 * sst.h, omx sst component header
 *
 * Copyright (c) 2009-2010 Wind River Systems, Inc.
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

#ifndef __WRS_OMXIL_INTEL_MRST_SST
#define __WRS_OMXIL_INTEL_MRST_SST

#include <OMX_Core.h>
#include <OMX_Component.h>

#include <cmodule.h>
#include <portbase.h>
#include <componentbase.h>

class MixAudioStreamCtrl : public WorkQueue
{
public:
    MixAudioStreamCtrl(MixAudio *mix);
    ~MixAudioStreamCtrl();

    typedef enum mix_audio_command_e {
        MIX_STREAM_START = 0,
        MIX_STREAM_STOP_DROP,
        MIX_STREAM_STOP_DRAIN,
        MIX_STREAM_PAUSE,
        MIX_STREAM_RESUME,
    } mix_audio_command_t;

    void SendCommand(mix_audio_command_t command);

private:
    mix_audio_command_t *PopCommand(void);

    virtual void Work(void);

    struct queue q;
    pthread_mutex_t lock;

    MixAudio *mix;
};

class MrstSstComponent : public ComponentBase
{
public:
    /*
     * constructor & destructor
     */
    MrstSstComponent();
    ~MrstSstComponent();

private:
    /*
     * component methods & helpers
     */
    /* implement ComponentBase::ComponentAllocatePorts */
    virtual OMX_ERRORTYPE ComponentAllocatePorts(void);

    /* implement ComponentBase::ComponentGet/SetPatameter */
    virtual OMX_ERRORTYPE
    ComponentGetParameter(OMX_INDEXTYPE nParamIndex,
                          OMX_PTR pComponentParameterStructure);
    virtual OMX_ERRORTYPE
    ComponentSetParameter(OMX_INDEXTYPE nIndex,
                          OMX_PTR pComponentParameterStructure);

    /* implement ComponentBase::ComponentGet/SetConfig */
    virtual OMX_ERRORTYPE
    ComponentGetConfig(OMX_INDEXTYPE nIndex,
                       OMX_PTR pComponentConfigStructure);
    virtual OMX_ERRORTYPE
    ComponentSetConfig(OMX_INDEXTYPE nIndex,
                       OMX_PTR pComponentConfigStructure);

    /* implement ComponentBase::Processor[*] */
    virtual OMX_ERRORTYPE ProcessorInit(void);  /* Loaded to Idle */
    virtual OMX_ERRORTYPE ProcessorDeinit(void);/* Idle to Loaded */
    virtual OMX_ERRORTYPE ProcessorStart(void); /* Idle to Executing/Pause */
    virtual OMX_ERRORTYPE ProcessorStop(void);  /* Executing/Pause to Idle */
    virtual OMX_ERRORTYPE ProcessorPause(void); /* Executing to Pause */
    virtual OMX_ERRORTYPE ProcessorResume(void);/* Pause to Executing */
    virtual OMX_ERRORTYPE ProcessorProcess(OMX_BUFFERHEADERTYPE ***pBuffers,
                                           buffer_retain_t *retain,
                                           OMX_U32 nr_buffers);

    OMX_ERRORTYPE __AllocateMp3Port(OMX_U32 port_index, OMX_DIRTYPE dir);
    OMX_ERRORTYPE __AllocateAacPort(OMX_U32 port_index, OMX_DIRTYPE dir);
    OMX_ERRORTYPE __AllocatePcmPort(OMX_U32 port_index, OMX_DIRTYPE dir);

    /* end of component methods & helpers */

    /*
     * acp setting helpers
     */
    OMX_ERRORTYPE __Mp3ChangeAcpWithConfigHeader(const unsigned char *buffer,
            bool *acp_changed);
    OMX_ERRORTYPE __AacChangeAcpWithConfigHeader(const unsigned char *buffer,
            bool *acp_changed);
    OMX_ERRORTYPE ChangeAcpWithConfigHeader(const unsigned char *buffer,
                                            bool *acp_changed);

    OMX_ERRORTYPE __Mp3ChangeAcpWithPortParam(MixAudioConfigParams *acp,
            PortMp3 *port,
            bool *acp_changed);
    OMX_ERRORTYPE __AacChangeAcpWithPortParam(MixAudioConfigParams *acp,
            PortAac *port,
            bool *acp_changed);
    OMX_ERRORTYPE ChangeAcpWithPortParam(MixAudioConfigParams *acp,
                                         PortBase *port,
                                         bool *acp_changed);

    OMX_ERRORTYPE __PcmChangePortParamWithAcp(MixAudioConfigParams *acp,
            PortPcm *port);
    OMX_ERRORTYPE __Mp3ChangePortParamWithAcp(MixAudioConfigParams *acp,
            PortMp3 *port);
    OMX_ERRORTYPE __AacChangePortParamWithAcp(MixAudioConfigParams *acp,
            PortAac *port);
    OMX_ERRORTYPE ChangePortParamWithAcp(void);

    /* end of acp setting helpers */

    /* mix audio */
    MixAudio *mix;
    MixAudioConfigParams *acp;
    MixIOVec *mixio_in, *mixio_out;

    MixAudioStreamCtrl *mix_stream_ctrl;

    OMX_AUDIO_CODINGTYPE coding_type;
    MixCodecMode codec_mode;

    OMX_U8 *codecdata;

    /* constant */
    /* ports */
    const static OMX_U32 NR_PORTS = 2;
    const static OMX_U32 INPORT_INDEX = 0;
    const static OMX_U32 OUTPORT_INDEX = 1;

    /* buffer */
    const static OMX_U32 INPORT_MP3_ACTUAL_BUFFER_COUNT = 5;
    const static OMX_U32 INPORT_MP3_MIN_BUFFER_COUNT = 1;
    const static OMX_U32 INPORT_MP3_BUFFER_SIZE = 4096;
    const static OMX_U32 OUTPORT_MP3_ACTUAL_BUFFER_COUNT = 2;
    const static OMX_U32 OUTPORT_MP3_MIN_BUFFER_COUNT = 1;
    const static OMX_U32 OUTPORT_MP3_BUFFER_SIZE = 1024;
    const static OMX_U32 INPORT_AAC_ACTUAL_BUFFER_COUNT = 5;
    const static OMX_U32 INPORT_AAC_MIN_BUFFER_COUNT = 1;
    const static OMX_U32 INPORT_AAC_BUFFER_SIZE = 4096;
    const static OMX_U32 OUTPORT_AAC_ACTUAL_BUFFER_COUNT = 2;
    const static OMX_U32 OUTPORT_AAC_MIN_BUFFER_COUNT = 1;
    const static OMX_U32 OUTPORT_AAC_BUFFER_SIZE = 2048;
    const static OMX_U32 INPORT_PCM_ACTUAL_BUFFER_COUNT = 2;
    const static OMX_U32 INPORT_PCM_MIN_BUFFER_COUNT = 1;
    const static OMX_U32 INPORT_PCM_BUFFER_SIZE = 4096;
    const static OMX_U32 OUTPORT_PCM_ACTUAL_BUFFER_COUNT = 5;
    const static OMX_U32 OUTPORT_PCM_MIN_BUFFER_COUNT = 1;
    const static OMX_U32 OUTPORT_PCM_BUFFER_SIZE = 16384;
};

#endif /* __WRS_OMXIL_INTEL_MRST_SST */
