#include "mxwavepresenter.h"

#include "decomp.h"
#include "mxdssound.h"
#include "mxomni.h"
#include "mxsoundmanager.h"

#include <limits.h>

DECOMP_SIZE_ASSERT(MxWavePresenter, 0x6c);
DECOMP_SIZE_ASSERT(MxWavePresenter::WaveFormat, 0x1c);

// OFFSET: LEGO1 0x1000d640
MxWavePresenter::~MxWavePresenter()
{
	Destroy(TRUE);
}

// OFFSET: LEGO1 0x1000d6a0
void MxWavePresenter::Destroy()
{
	Destroy(FALSE);
}

// OFFSET: LEGO1 0x1000d6b0
undefined MxWavePresenter::VTable0x6c()
{
	return m_unk68;
}

// OFFSET: LEGO1 0x100b1ad0
void MxWavePresenter::Init()
{
	m_waveFormat = NULL;
	m_dsBuffer = NULL;
	m_length = 0;
	m_unk60 = 0;
	m_unk64 = 0;
	m_unk65 = FALSE;
	m_unk66 = FALSE;
	m_unk68 = 0;
}

// OFFSET: LEGO1 0x100b1af0
MxResult MxWavePresenter::AddToManager()
{
	MxResult result = MxSoundPresenter::AddToManager();
	Init();
	return result;
}

// OFFSET: LEGO1 0x100b1b10
void MxWavePresenter::Destroy(MxBool p_fromDestructor)
{
	if (m_dsBuffer) {
		m_dsBuffer->Stop();
		m_dsBuffer->Release();
	}

	if (m_waveFormat)
		delete[] ((MxU8*) m_waveFormat);

	Init();

	if (!p_fromDestructor)
		MxSoundPresenter::Destroy(FALSE);
}

// OFFSET: LEGO1 0x100b1b60
MxS8 MxWavePresenter::FUN_100b1b60()
{
	DWORD dwCurrentPlayCursor, dwCurrentWriteCursor;
	MxS8 result = -1;

	if (m_dsBuffer->GetCurrentPosition(&dwCurrentPlayCursor, &dwCurrentWriteCursor) == DS_OK)
		result = dwCurrentPlayCursor / m_length;

	return result;
}

// OFFSET: LEGO1 0x100b1ba0
MxBool MxWavePresenter::FUN_100b1ba0()
{
	return !m_unk65 || FUN_100b1b60() != m_unk64;
}

// OFFSET: LEGO1 0x100b1bd0 STUB
void MxWavePresenter::FUN_100b1bd0(void* p_audioPtr, MxU32 p_length)
{
	// Lock/Unlock on m_dsBuffer
	// TODO
}

// OFFSET: LEGO1 0x100b1cf0
void MxWavePresenter::ReadyTickle()
{
	MxStreamChunk* chunk = NextChunk();

	if (chunk) {
		m_waveFormat = (WaveFormat*) new MxU8[chunk->GetLength()];
		memcpy(m_waveFormat, chunk->GetData(), chunk->GetLength());
		m_subscriber->FUN_100b8390(chunk);
		ParseExtra();
		m_previousTickleStates |= 1 << (unsigned char) m_currentTickleState;
		m_currentTickleState = TickleState_Starting;
	}
}

// OFFSET: LEGO1 0x100b1d50
void MxWavePresenter::StartingTickle()
{
	MxStreamChunk* chunk = NextChunk();

	if (chunk && m_action->GetElapsedTime() >= chunk->GetTime()) {
		MxU32 length = chunk->GetLength();
		WAVEFORMATEX waveFormatEx;

		m_length = length;
		memset(&waveFormatEx, 0, sizeof(waveFormatEx));

		waveFormatEx.wFormatTag = m_waveFormat->m_waveFormatEx.wFormatTag;
		waveFormatEx.nChannels = m_waveFormat->m_waveFormatEx.nChannels;
		waveFormatEx.nSamplesPerSec = m_waveFormat->m_waveFormatEx.nSamplesPerSec;
		waveFormatEx.nAvgBytesPerSec = m_waveFormat->m_waveFormatEx.nAvgBytesPerSec;
		waveFormatEx.nBlockAlign = m_waveFormat->m_waveFormatEx.nBlockAlign;
		waveFormatEx.wBitsPerSample = m_waveFormat->m_waveFormatEx.wBitsPerSample;

		if (waveFormatEx.wBitsPerSample == 8)
			m_unk67 = SCHAR_MAX;

		if (waveFormatEx.wBitsPerSample == 16)
			m_unk67 = 0;

		DSBUFFERDESC desc;
		memset(&desc, 0, sizeof(desc));
		desc.dwSize = sizeof(desc);

		if (m_unk66)
			desc.dwFlags = DSBCAPS_CTRL3D | DSBCAPS_CTRLFREQUENCY | DSBCAPS_CTRLVOLUME;
		else
			desc.dwFlags = DSBCAPS_CTRLFREQUENCY | DSBCAPS_CTRLPAN | DSBCAPS_CTRLVOLUME;

		if (m_action->GetFlags() & MxDSAction::Flag_Looping)
			desc.dwBufferBytes = m_waveFormat->m_waveFormatEx.nAvgBytesPerSec *
								 (m_action->GetDuration() / m_action->GetLoopCount()) / 1000;
		else
			desc.dwBufferBytes = 2 * length;

		desc.lpwfxFormat = &waveFormatEx;

		if (MSoundManager()->GetDirectSound()->CreateSoundBuffer(&desc, &m_dsBuffer, NULL) != DS_OK) {
			EndAction();
		}
		else {
			SetVolume(((MxDSSound*) m_action)->GetVolume());
			m_previousTickleStates |= 1 << (unsigned char) m_currentTickleState;
			m_currentTickleState = TickleState_Streaming;
		}
	}
}

// OFFSET: LEGO1 0x100b1ea0 STUB
void MxWavePresenter::StreamingTickle()
{
	// TODO
}

// OFFSET: LEGO1 0x100b20c0 STUB
void MxWavePresenter::DoneTickle()
{
	// TODO
}

// OFFSET: LEGO1 0x100b2130 STUB
void MxWavePresenter::AppendChunk(MxStreamChunk* p_chunk)
{
	// TODO
}

// OFFSET: LEGO1 0x100b2160 STUB
undefined4 MxWavePresenter::PutData()
{
	// TODO
	return 0;
}

// OFFSET: LEGO1 0x100b2280 STUB
void MxWavePresenter::EndAction()
{
	// TODO
}

// OFFSET: LEGO1 0x100b2300 STUB
void MxWavePresenter::SetVolume(MxU32 p_volume)
{
	// TODO
}

// OFFSET: LEGO1 0x100b2360 STUB
void MxWavePresenter::Enable(MxBool p_enable)
{
	// TODO
}

// OFFSET: LEGO1 0x100b23a0 STUB
void MxWavePresenter::ParseExtra()
{
	// TODO
}

// OFFSET: LEGO1 0x100b2440 STUB
void MxWavePresenter::VTable0x64()
{
	// TODO
}

// OFFSET: LEGO1 0x100b2470 STUB
void MxWavePresenter::VTable0x68()
{
	// TODO
}
