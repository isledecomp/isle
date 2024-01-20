#include "mxloopingflcpresenter.h"

#include "decomp.h"

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
	this->m_flags &= ~c_bit2;
	this->m_flags &= ~c_bit3;
}

// FUNCTION: LEGO1 0x100b4430
void MxLoopingFlcPresenter::Destroy(MxBool p_fromDestructor)
{
	m_criticalSection.Enter();
	Init();
	m_criticalSection.Leave();

	if (!p_fromDestructor)
		MxFlcPresenter::Destroy(FALSE);
}

// FUNCTION: LEGO1 0x100b4470
void MxLoopingFlcPresenter::NextFrame()
{
	MxStreamChunk* chunk = NextChunk();

	if (chunk->GetFlags() & MxDSChunk::c_end)
		ProgressTickleState(e_repeating);
	else {
		LoadFrame(chunk);
		LoopChunk(chunk);
		m_elapsedDuration += m_flcHeader->speed;
	}

	m_subscriber->DestroyChunk(chunk);
}

// FUNCTION: LEGO1 0x100b44c0
void MxLoopingFlcPresenter::VTable0x88()
{
	if (m_action->GetDuration() < m_elapsedDuration)
		ProgressTickleState(e_unk5);
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
	for (MxS16 i = 0; i < m_unk0x5c; i++) {
		if (!m_loopingChunkCursor->HasMatch()) {
			MxStreamChunk* chunk;
			MxStreamChunkListCursor cursor(m_loopingChunks);

			cursor.Last(chunk);
			MxLong time = chunk->GetTime();

			cursor.First(chunk);

			time -= chunk->GetTime();
			time += m_flcHeader->speed;

			cursor.Reset();
			while (cursor.Next(chunk))
				chunk->SetTime(chunk->GetTime() + time);

			m_loopingChunkCursor->Next();
		}

		MxStreamChunk* chunk;
		m_loopingChunkCursor->Current(chunk);

		if (m_action->GetElapsedTime() < chunk->GetTime())
			break;

		VTable0x88();

		m_loopingChunkCursor->Next(chunk);

		if (m_currentTickleState != e_repeating)
			break;
	}
}

// FUNCTION: LEGO1 0x100b4860
MxResult MxLoopingFlcPresenter::AddToManager()
{
	MxResult result = FAILURE;
	MxBool locked = FALSE;

	if (MxFlcPresenter::AddToManager() == SUCCESS) {
		m_criticalSection.Enter();
		locked = TRUE;
		result = SUCCESS;
	}

	if (locked)
		m_criticalSection.Leave();

	return result;
}

// FUNCTION: LEGO1 0x100b48a0
void MxLoopingFlcPresenter::Destroy()
{
	Destroy(FALSE);
}
