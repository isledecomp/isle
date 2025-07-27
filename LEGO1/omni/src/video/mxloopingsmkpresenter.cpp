#include "mxloopingsmkpresenter.h"

#include "mxautolock.h"
#include "mxdsmediaaction.h"
#include "mxdssubscriber.h"

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
	m_elapsedDuration = 0;
	SetUseSurface(FALSE);
	SetUseVideoMemory(FALSE);
}

// FUNCTION: LEGO1 0x100b49d0
void MxLoopingSmkPresenter::Destroy(MxBool p_fromDestructor)
{
	ENTER(m_criticalSection);
	Init();
	m_criticalSection.Leave();

	if (!p_fromDestructor) {
		MxSmkPresenter::Destroy();
	}
}

// FUNCTION: LEGO1 0x100b4a00
void MxLoopingSmkPresenter::ResetCurrentFrameAtEnd()
{
	if (m_mxSmk.m_smackTag.Frames == m_currentFrame) {
		m_currentFrame = 0;
		// TODO: struct incorrect, Palette at wrong offset?
		memset(&m_mxSmk.m_smackTag.Palette[4], 0, sizeof(m_mxSmk.m_smackTag.Palette));
	}
}

// FUNCTION: LEGO1 0x100b4a30
void MxLoopingSmkPresenter::NextFrame()
{
	MxStreamChunk* chunk = NextChunk();

	if (chunk->GetChunkFlags() & DS_CHUNK_END_OF_STREAM) {
		ProgressTickleState(e_repeating);
	}
	else {
		LoadFrame(chunk);
		LoopChunk(chunk);
		m_elapsedDuration += 1000 / ((MxDSMediaAction*) m_action)->GetFramesPerSecond();
	}

	m_subscriber->FreeDataChunk(chunk);
}

// FUNCTION: LEGO1 0x100b4a90
void MxLoopingSmkPresenter::LoadFrameIfRequired()
{
	if (m_action->GetDuration() < m_elapsedDuration) {
		ProgressTickleState(e_freezing);
	}
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
	for (MxS16 i = 0; i < m_frameLoadTickleCount; i++) {
		if (!m_loopingChunkCursor->HasMatch()) {
			MxStreamChunk* chunk;
			MxStreamChunkListCursor cursor(m_loopingChunks);

			cursor.Last(chunk);
			MxLong time = chunk->GetTime();

			cursor.First(chunk);

			time -= chunk->GetTime();
			time += 1000 / ((MxDSMediaAction*) m_action)->GetFramesPerSecond();

			cursor.Reset();
			while (cursor.Next(chunk)) {
				chunk->SetTime(chunk->GetTime() + time);
			}

			m_loopingChunkCursor->Next();
		}

		MxStreamChunk* chunk;
		m_loopingChunkCursor->Current(chunk);

		if (m_action->GetElapsedTime() < chunk->GetTime()) {
			break;
		}

		LoadFrameIfRequired();

		m_loopingChunkCursor->Next(chunk);

		if (m_currentTickleState != e_repeating) {
			break;
		}
	}
}

// FUNCTION: LEGO1 0x100b4cd0
MxResult MxLoopingSmkPresenter::AddToManager()
{
	AUTOLOCK(m_criticalSection);
	return MxSmkPresenter::AddToManager();
}

// FUNCTION: LEGO1 0x100b4d40
void MxLoopingSmkPresenter::Destroy()
{
	Destroy(FALSE);
}
