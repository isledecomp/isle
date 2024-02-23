#include "mxmidipresenter.h"

#include "decomp.h"
#include "mxautolocker.h"
#include "mxdssound.h"
#include "mxmusicmanager.h"

DECOMP_SIZE_ASSERT(MxMIDIPresenter, 0x58);

// FUNCTION: LEGO1 0x100c25e0
MxMIDIPresenter::MxMIDIPresenter()
{
	Init();
}

// FUNCTION: LEGO1 0x100c27c0
MxMIDIPresenter::~MxMIDIPresenter()
{
	Destroy(TRUE);
}

// FUNCTION: LEGO1 0x100c2820
void MxMIDIPresenter::Init()
{
	m_chunk = NULL;
}

// FUNCTION: LEGO1 0x100c2830
void MxMIDIPresenter::Destroy(MxBool p_fromDestructor)
{
	if (MusicManager()) {
		MusicManager()->DeinitializeMIDI();
	}

	m_criticalSection.Enter();

	if (m_subscriber && m_chunk) {
		m_subscriber->FreeDataChunk(m_chunk);
	}
	Init();

	m_criticalSection.Leave();

	if (!p_fromDestructor) {
		MxMusicPresenter::Destroy();
	}
}

// FUNCTION: LEGO1 0x100c2890
void MxMIDIPresenter::ReadyTickle()
{
	MxStreamChunk* chunk = NextChunk();

	if (chunk) {
		m_subscriber->FreeDataChunk(chunk);
		ParseExtra();
		ProgressTickleState(e_starting);
	}
}

// FUNCTION: LEGO1 0x100c28d0
void MxMIDIPresenter::StartingTickle()
{
	MxStreamChunk* chunk = CurrentChunk();

	if (chunk && m_action->GetElapsedTime() >= chunk->GetTime()) {
		ProgressTickleState(e_streaming);
	}
}

// FUNCTION: LEGO1 0x100c2910
void MxMIDIPresenter::StreamingTickle()
{
	if (m_chunk) {
		ProgressTickleState(e_done);
	}
	else {
		m_chunk = NextChunk();
	}
}

// FUNCTION: LEGO1 0x100c2940
void MxMIDIPresenter::DoneTickle()
{
	if (!MusicManager()->GetMIDIInitialized()) {
		EndAction();
	}
}

// FUNCTION: LEGO1 0x100c2960
void MxMIDIPresenter::Destroy()
{
	Destroy(FALSE);
}

// FUNCTION: LEGO1 0x100c2970
MxResult MxMIDIPresenter::PutData()
{
	m_criticalSection.Enter();

	if (m_currentTickleState == e_streaming && m_chunk && !MusicManager()->GetMIDIInitialized()) {
		SetVolume(((MxDSSound*) m_action)->GetVolume());

		if (MusicManager()->InitializeMIDI(m_chunk->GetData(), 1) != SUCCESS) {
			EndAction();
		}
	}

	m_criticalSection.Leave();
	return SUCCESS;
}

// FUNCTION: LEGO1 0x100c29e0
void MxMIDIPresenter::EndAction()
{
	if (m_action) {
		MxAutoLocker lock(&m_criticalSection);

		MxMediaPresenter::EndAction();
		MusicManager()->DeinitializeMIDI();
	}
}

// FUNCTION: LEGO1 0x100c2a60
void MxMIDIPresenter::SetVolume(MxS32 p_volume)
{
	m_volume = p_volume;
	MusicManager()->SetMultiplier(p_volume);
}
