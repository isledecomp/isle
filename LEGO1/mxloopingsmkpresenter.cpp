#include "mxloopingsmkpresenter.h"

#include "mxautolocker.h"
#include "mxdsmediaaction.h"

DECOMP_SIZE_ASSERT(MxLoopingSmkPresenter, 0x724);

// FUNCTION: LEGO1 0x100b48b0
MxLoopingSmkPresenter::MxLoopingSmkPresenter()
{
	Init();
}

// FUNCTION: LEGO1 0x100b4950
MxLoopingSmkPresenter::~MxLoopingSmkPresenter()
{
	Destroy(TRUE);
}

// FUNCTION: LEGO1 0x100b49b0
void MxLoopingSmkPresenter::Init()
{
	this->m_elapsedDuration = 0;
	this->m_flags &= 0xfd;
	this->m_flags &= 0xfb;
}

// FUNCTION: LEGO1 0x100b49d0
void MxLoopingSmkPresenter::Destroy(MxBool p_fromDestructor)
{
	m_criticalSection.Enter();
	Init();
	m_criticalSection.Leave();

	if (!p_fromDestructor)
		MxSmkPresenter::Destroy();
}

// FUNCTION: LEGO1 0x100b4a00
void MxLoopingSmkPresenter::VTable0x88()
{
	if (m_mxSmack.m_smackTag.Frames == m_unk0x71c) {
		m_unk0x71c = 0;
		// TODO: struct incorrect, Palette at wrong offset?
		memset(&m_mxSmack.m_smackTag.Palette[4], 0, sizeof(m_mxSmack.m_smackTag.Palette));
	}
}

// FUNCTION: LEGO1 0x100b4a30
void MxLoopingSmkPresenter::NextFrame()
{
	MxStreamChunk* chunk = NextChunk();

	if (chunk->GetFlags() & MxStreamChunk::Flag_Bit2) {
		m_previousTickleStates |= 1 << (unsigned char) m_currentTickleState;
		m_currentTickleState = TickleState_Repeating;
	}
	else {
		LoadFrame(chunk);
		AppendChunk(chunk);
		m_elapsedDuration += 1000 / ((MxDSMediaAction*) m_action)->GetFramesPerSecond();
	}

	m_subscriber->FUN_100b8390(chunk);
}

// FUNCTION: LEGO1 0x100b4a90
void MxLoopingSmkPresenter::VTable0x8c()
{
	if (m_action->GetDuration() < m_elapsedDuration) {
		m_previousTickleStates |= 1 << (unsigned char) m_currentTickleState;
		m_currentTickleState = TickleState_unk5;
	}
	else {
		MxStreamChunk* chunk;
		m_cursor->Current(chunk);
		LoadFrame(chunk);
		m_elapsedDuration += 1000 / ((MxDSMediaAction*) m_action)->GetFramesPerSecond();
	}
}

// FUNCTION: LEGO1 0x100b4b00
void MxLoopingSmkPresenter::RepeatingTickle()
{
	for (MxS16 i = 0; i < m_unk0x5c; i++) {
		if (!m_cursor->HasMatch()) {
			MxStreamChunk* chunk;
			MxStreamChunkListCursor cursor(m_chunks);

			cursor.Last(chunk);
			MxLong time = chunk->GetTime();

			cursor.First(chunk);

			time -= chunk->GetTime();
			time += 1000 / ((MxDSMediaAction*) m_action)->GetFramesPerSecond();

			cursor.Reset();
			while (cursor.Next(chunk))
				chunk->SetTime(chunk->GetTime() + time);

			m_cursor->Advance();
		}

		MxStreamChunk* chunk;
		m_cursor->Current(chunk);

		if (m_action->GetElapsedTime() < chunk->GetTime())
			break;

		VTable0x8c();

		m_cursor->Next(chunk);

		if (m_currentTickleState != TickleState_Repeating)
			break;
	}
}

// FUNCTION: LEGO1 0x100b4cd0
MxResult MxLoopingSmkPresenter::AddToManager()
{
	MxAutoLocker lock(&m_criticalSection);
	return MxSmkPresenter::AddToManager();
}

// FUNCTION: LEGO1 0x100b4d40
void MxLoopingSmkPresenter::Destroy()
{
	Destroy(FALSE);
}
