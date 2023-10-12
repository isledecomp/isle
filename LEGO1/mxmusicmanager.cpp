#include "mxmusicmanager.h"
#include "mxticklemanager.h"
#include "mxomni.h"

#include <windows.h>

DECOMP_SIZE_ASSERT(MxMusicManager, 0x58);

// OFFSET: LEGO1 0x100c05a0
MxMusicManager::MxMusicManager()
{
  Init();
}

// OFFSET: LEGO1 0x100c0630
MxMusicManager::~MxMusicManager()
{
  LockedReinitialize(TRUE);
}

// OFFSET: LEGO1 0x100c0b20
void MxMusicManager::DeinitializeMIDI()
{
  m_criticalSection.Enter();

  if (this->m_MIDIInitialized)
  {
    this->m_MIDIInitialized = FALSE;
    midiStreamStop(this->m_MIDIStreamH);
    midiOutUnprepareHeader(this->m_MIDIStreamH, this->m_MIDIHdrP, sizeof(MIDIHDR));
    midiOutSetVolume(this->m_MIDIStreamH, this->m_MIDIVolume);
    midiStreamClose(this->m_MIDIStreamH);
    delete this->m_MIDIHdrP;
    this->InitData();
  }

  this->m_criticalSection.Leave();
}

// OFFSET: LEGO1 0x100c0690
void MxMusicManager::Init()
{
  this->m_multiplier = 100;
  InitData();
}

// OFFSET: LEGO1 0x100c06a0
void MxMusicManager::InitData()
{
  this->m_MIDIStreamH = 0;
  this->m_MIDIInitialized = FALSE;
  this->m_unk38 = 0;
  this->m_unk3c = 0;
  this->m_unk40 = 0;
  this->m_unk44 = 0;
  this->m_unk48 = 0;
  this->m_MIDIHdrP = NULL;
}

// OFFSET: LEGO1 0x100c06c0
void MxMusicManager::LockedReinitialize(MxBool p_skipDestroy)
{
  if (this->m_thread)
  {
    this->m_thread->Terminate();
    if (this->m_thread)
    {
      delete m_thread;
    }
  }
  else
  {
    TickleManager()->UnregisterClient(this);
  }

  this->m_criticalSection.Enter();
  DeinitializeMIDI();
  Init();
  this->m_criticalSection.Leave();

  if (!p_skipDestroy)
  {
    MxAudioManager::Destroy();
  }
}

// OFFSET: LEGO1 0x100c0930
void MxMusicManager::Destroy()
{
  LockedReinitialize(FALSE);
}

// OFFSET: LEGO1 0x100c09a0
MxS32 MxMusicManager::CalculateVolume(MxS32 p_volume)
{
  MxS32 result = (p_volume * 0xffff) / 100;
  return (result << 0x10) | result;
}

// OFFSET: LEGO1 0x100c07f0
void MxMusicManager::SetMIDIVolume()
{
  MxS32 result = (this->m_volume * this->m_multiplier) / 0x64;
  HMIDISTRM streamHandle = this->m_MIDIStreamH;

  if (streamHandle)
  {
    MxS32 volume = CalculateVolume(result);
    midiOutSetVolume(streamHandle, volume);
  }
}

// OFFSET: LEGO1 0x100c0940
void MxMusicManager::SetVolume(MxS32 p_volume)
{
  MxAudioManager::SetVolume(p_volume);
  this->m_criticalSection.Enter();
  SetMIDIVolume();
  this->m_criticalSection.Leave();
}

// OFFSET: LEGO1 0x100c0840
MxResult MxMusicManager::StartMIDIThread(MxU32 p_frequencyMS, MxBool p_noRegister)
{
  MxResult status = FAILURE;
  MxBool locked = FALSE;

  MxResult result = MxAudioManager::InitPresenters();
  if (result == SUCCESS)
  {
    if (p_noRegister)
    {
      this->m_criticalSection.Enter();
      locked = TRUE;
      this->m_thread = new MxTickleThread(this, p_frequencyMS);

      if (this->m_thread)
      {
        if (this->m_thread->Start(0, 0) == SUCCESS)
        {
          status = SUCCESS;
        }
      }
    }
    else
    {
      TickleManager()->RegisterClient(this, p_frequencyMS);
      status = SUCCESS;
    }
  }

  if (status != SUCCESS)
  {
    Destroy();
  }

  if (locked)
  {
    this->m_criticalSection.Leave();
  }

  return status;
}