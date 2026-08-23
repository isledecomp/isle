#include "mxloopingflcpresenter.h"

#include "decomp.h"
#include "mxdsaction.h"
#include "mxdssubscriber.h"

DECOMP_SIZE_ASSERT(MxLoopingFlcPresenter, 0x6c);

// FUNCTION: LEGO1 0x100b4310
MxLoopingFlcPresenter::MxLoopingFlcPresenter()
{
	Init();
}

// FUNCTION: LEGO1 0x100b43b0
MxLoopingFlcPresenter::~MxLoopingFlcPresenter()
{
	Destroy(TRUE);
}

// FUNCTION: LEGO1 0x100b4410
void MxLoopingFlcPresenter::Init()
{
	this->m_elapsedDuration = 0;
	SetUseSurface(FALSE);
	SetUseVideoMemory(FALSE);
}

// FUNCTION: LEGO1 0x100b4430
void MxLoopingFlcPresenter::Destroy(MxBool p_fromDestructor)
{
	ENTER(m_criticalSection);
	Init();
	m_criticalSection.Leave();

	if (!p_fromDestructor) {
		MxFlcPresenter::Destroy(FALSE);
	}
}

// FUNCTION: LEGO1 0x100b4470
void MxLoopingFlcPresenter::NextFrame()
{
	MxStreamChunk* chunk = NextChunk();

	if (chunk->GetChunkFlags() & DS_CHUNK_END_OF_STREAM) {
		ProgressTickleState(e_repeating);
	}
	else {
		LoadFrame(chunk);
		LoopChunk(chunk);
		m_elapsedDuration += m_flcHeader->speed;
	}

	m_subscriber->FreeDataChunk(chunk);
}

// FUNCTION: LEGO1 0x100b44c0
void MxLoopingFlcPresenter::LoadFrameIfRequired()
{
	if (m_action->GetDuration() < m_elapsedDuration) {
		ProgressTickleState(e_freezing);
	}
	else {
		MxStreamChunk* chunk;
		m_loopingChunkCursor->Current(chunk);
		LoadFrame(chunk);
		m_elapsedDuration += m_flcHeader->speed;
	}
}

// FUNCTION: LEGO1 0x100b4520
void MxLoopingFlcPresenter::RepeatingTickle()
{
	for (MxS16 i = 0; i < m_frameLoadTickleCount; i++) {
		if (!m_loopingChunkCursor->HasMatch()) {
			MxStreamChunk* chunk;
			MxStreamChunkListCursor cursor(m_loopingChunks);

			cursor.Last(chunk);
			MxLong time = chunk->GetTime();

			cursor.First(chunk);

			time -= chunk->GetTime();
			time += m_flcHeader->speed;

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

// FUNCTION: LEGO1 0x100b4860
MxResult MxLoopingFlcPresenter::AddToManager()
{
	MxResult result = FAILURE;
	MxBool locked = FALSE;

	if (MxFlcPresenter::AddToManager() == SUCCESS) {
		ENTER(m_criticalSection);
		locked = TRUE;
		result = SUCCESS;
	}

	if (locked) {
		m_criticalSection.Leave();
	}

	return result;
}

// FUNCTION: LEGO1 0x100b48a0
void MxLoopingFlcPresenter::Destroy()
{
	Destroy(FALSE);
}
