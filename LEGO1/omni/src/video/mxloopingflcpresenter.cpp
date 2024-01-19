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
		m_unk0x68 += m_flcHeader->speed;
	}

	m_subscriber->DestroyChunk(chunk);
}
