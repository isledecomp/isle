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
	this->m_flags &= ~Flag_Bit2;
	this->m_flags &= ~Flag_Bit3;
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
	if (m_mxSmack.m_smackTag.Frames == m_currentFrame) {
		m_currentFrame = 0;
		// TODO: struct incorrect, Palette at wrong offset?
		memset(&m_mxSmack.m_smackTag.Palette[4], 0, sizeof(m_mxSmack.m_smackTag.Palette));
	}
}

// FUNCTION: LEGO1 0x100b4a30
void MxLoopingSmkPresenter::NextFrame()
{
	MxStreamChunk* chunk = NextChunk();

	if (chunk->GetFlags() & MxDSChunk::Flag_End)
		ProgressTickleState(TickleState_Repeating);
	else {
		LoadFrame(chunk);
		LoopChunk(chunk);
		m_elapsedDuration += 1000 / ((MxDSMediaAction*) m_action)->GetFramesPerSecond();
	}

	m_subscriber->DestroyChunk(chunk);
}

// FUNCTION: LEGO1 0x100b4a90
void MxLoopingSmkPresenter::VTable0x8c()
{
	if (m_action->GetDuration() < m_elapsedDuration)
		ProgressTickleState(TickleState_unk5);
	else {
		MxStreamChunk* chunk;
		m_loopingChunkCursor->Current(chunk);
		LoadFrame(chunk);
		m_elapsedDuration += 1000 / ((MxDSMediaAction*) m_action)->GetFramesPerSecond();
	}
}

// FUNCTION: LEGO1 0x100b4b00
void MxLoopingSmkPresenter::RepeatingTickle()
{
	for (MxS16 i = 0; i < m_unk0x5c; i++) {
		if (!m_loopingChunkCursor->HasMatch()) {
			MxStreamChunk* chunk;
			MxStreamChunkListCursor cursor(m_loopingChunks);

			cursor.Last(chunk);
			MxLong time = chunk->GetTime();

			cursor.First(chunk);

			time -= chunk->GetTime();
			time += 1000 / ((MxDSMediaAction*) m_action)->GetFramesPerSecond();

			cursor.Reset();
			while (cursor.Next(chunk))
				chunk->SetTime(chunk->GetTime() + time);

			m_loopingChunkCursor->Next();
		}

		MxStreamChunk* chunk;
		m_loopingChunkCursor->Current(chunk);

		if (m_action->GetElapsedTime() < chunk->GetTime())
			break;

		VTable0x8c();

		m_loopingChunkCursor->Next(chunk);

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
