#include "mxloopingmidipresenter.h"

#include "decomp.h"
#include "mxdssound.h"
#include "mxmusicmanager.h"
#include "mxomni.h"

DECOMP_SIZE_ASSERT(MxLoopingMIDIPresenter, 0x58);

// FUNCTION: LEGO1 0x100c2a80
void MxLoopingMIDIPresenter::StreamingTickle()
{
	if (m_action->GetLoopCount()) {
		MxMIDIPresenter::StreamingTickle();
		return;
	}

	if (!m_chunk) {
		m_chunk = NextChunk();
		return;
	}

	if (m_chunk->GetTime() + m_action->GetDuration() <= m_action->GetElapsedTime())
		ProgressTickleState(e_done);
}

// FUNCTION: LEGO1 0x100c2ae0
void MxLoopingMIDIPresenter::DoneTickle()
{
	if (m_action->GetLoopCount())
		MxMIDIPresenter::DoneTickle();
	else
		EndAction();
}

// FUNCTION: LEGO1 0x100c2b00
MxResult MxLoopingMIDIPresenter::PutData()
{
	m_criticalSection.Enter();

	if (m_currentTickleState == e_streaming && m_chunk && !MusicManager()->GetMIDIInitialized()) {
		SetVolume(((MxDSSound*) m_action)->GetVolume());
		MusicManager()->InitializeMIDI(m_chunk->GetData(), !m_action->GetLoopCount() ? -1 : m_action->GetLoopCount());
	}

	m_criticalSection.Leave();
	return SUCCESS;
}
