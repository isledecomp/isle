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
	this->m_unk0x68 = 0;
	this->m_flags &= ~Flag_Bit2;
	this->m_flags &= ~Flag_Bit3;
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

	if (chunk->GetFlags() & MxStreamChunk::Flag_Bit2) {
		m_previousTickleStates |= 1 << (unsigned char) m_currentTickleState;
		m_currentTickleState = TickleState_Repeating;
	}
	else {
		LoadFrame(chunk);
		AppendChunk(chunk);
		m_unk0x68 += m_flicHeader->speed;
	}

	m_subscriber->FUN_100b8390(chunk);
}
