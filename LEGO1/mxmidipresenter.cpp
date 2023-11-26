#include "mxmidipresenter.h"

#include "decomp.h"
#include "legoomni.h"
#include "mxautolocker.h"
#include "mxdssound.h"
#include "mxmusicmanager.h"

DECOMP_SIZE_ASSERT(MxMIDIPresenter, 0x58);

// OFFSET: LEGO1 0x100c25e0
MxMIDIPresenter::MxMIDIPresenter()
{
	Init();
}

// OFFSET: LEGO1 0x100c27c0
MxMIDIPresenter::~MxMIDIPresenter()
{
	Destroy(TRUE);
}

// OFFSET: LEGO1 0x100c2820
void MxMIDIPresenter::Init()
{
	m_chunk = NULL;
}

// OFFSET: LEGO1 0x100c2830
void MxMIDIPresenter::Destroy(MxBool p_fromDestructor)
{
	if (MusicManager()) {
		MusicManager()->DeinitializeMIDI();
	}

	m_criticalSection.Enter();

	if (m_subscriber && m_chunk)
		m_subscriber->FUN_100b8390(m_chunk);
	Init();

	m_criticalSection.Leave();

	if (!p_fromDestructor)
		MxMusicPresenter::Destroy();
}

// OFFSET: LEGO1 0x100c2890
void MxMIDIPresenter::ReadyTickle()
{
	MxStreamChunk* chunk = NextChunk();

	if (chunk) {
		m_subscriber->FUN_100b8390(chunk);
		ParseExtra();
		m_previousTickleStates |= 1 << (unsigned char) m_currentTickleState;
		m_currentTickleState = TickleState_Starting;
	}
}

// OFFSET: LEGO1 0x100c28d0
void MxMIDIPresenter::StartingTickle()
{
	MxStreamChunk* chunk = FUN_100b5650();

	if (chunk && m_action->GetElapsedTime() >= chunk->GetTime()) {
		m_previousTickleStates |= 1 << (unsigned char) m_currentTickleState;
		m_currentTickleState = TickleState_Streaming;
	}
}

// OFFSET: LEGO1 0x100c2910
void MxMIDIPresenter::StreamingTickle()
{
	if (m_chunk) {
		m_previousTickleStates |= 1 << (unsigned char) m_currentTickleState;
		m_currentTickleState = TickleState_Done;
	}
	else
		m_chunk = NextChunk();
}

// OFFSET: LEGO1 0x100c2940
void MxMIDIPresenter::DoneTickle()
{
	if (!MusicManager()->GetMIDIInitialized())
		EndAction();
}

// OFFSET: LEGO1 0x100c2960
void MxMIDIPresenter::Destroy()
{
	Destroy(FALSE);
}

// OFFSET: LEGO1 0x100c2970
MxResult MxMIDIPresenter::PutData()
{
	m_criticalSection.Enter();

	if (m_currentTickleState == TickleState_Streaming && m_chunk && !MusicManager()->GetMIDIInitialized()) {
		SetVolume(((MxDSSound*) m_action)->GetVolume());

		if (MusicManager()->FUN_100c09c0(m_chunk->GetData(), 1))
			EndAction();
	}

	m_criticalSection.Leave();
	return SUCCESS;
}

// OFFSET: LEGO1 0x100c29e0
void MxMIDIPresenter::EndAction()
{
	if (m_action) {
		MxAutoLocker lock(&m_criticalSection);

		MxMediaPresenter::EndAction();
		MusicManager()->DeinitializeMIDI();
	}
}

// OFFSET: LEGO1 0x100c2a60
void MxMIDIPresenter::SetVolume(MxS32 p_volume)
{
	m_volume = p_volume;
	MusicManager()->SetMultiplier(p_volume);
}
