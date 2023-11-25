#include "mxloopingmidipresenter.h"

#include "decomp.h"
#include "mxdssound.h"
#include "mxmusicmanager.h"
#include "mxomni.h"

DECOMP_SIZE_ASSERT(MxLoopingMIDIPresenter, 0x58);

// OFFSET: LEGO1 0x100b1830 TEMPLATE
// MxLoopingMIDIPresenter::ClassName

// OFFSET: LEGO1 0x100b1840 TEMPLATE
// MxLoopingMIDIPresenter::IsA

// OFFSET: LEGO1 0x100b19c0 TEMPLATE
// MxLoopingMIDIPresenter::`scalar deleting destructor'

// OFFSET: LEGO1 0x100c2a80
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

	if (m_chunk->GetTime() + m_action->GetDuration() <= m_action->GetElapsedTime()) {
		m_previousTickleStates |= 1 << (unsigned char) m_currentTickleState;
		m_currentTickleState = TickleState_Done;
	}
}

// OFFSET: LEGO1 0x100c2ae0
void MxLoopingMIDIPresenter::DoneTickle()
{
	if (m_action->GetLoopCount())
		MxMIDIPresenter::DoneTickle();
	else
		EndAction();
}

// OFFSET: LEGO1 0x100c2b00
undefined4 MxLoopingMIDIPresenter::PutData()
{
	m_criticalSection.Enter();

	if (m_currentTickleState == TickleState_Streaming && m_chunk && !MusicManager()->GetMIDIInitialized()) {
		SetVolume(((MxDSSound*) m_action)->GetVolume());
		MusicManager()->FUN_100c09c0(m_chunk->GetData(), !m_action->GetLoopCount() ? -1 : m_action->GetLoopCount());
	}

	m_criticalSection.Leave();
	return 0;
}
