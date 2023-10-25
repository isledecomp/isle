#include "mxloopingsmkpresenter.h"

#include "decomp.h"

DECOMP_SIZE_ASSERT(MxLoopingSmkPresenter, 0x724);

// OFFSET: LEGO1 0x100b48b0
MxLoopingSmkPresenter::MxLoopingSmkPresenter()
{
	Init();
}

// OFFSET: LEGO1 0x100b4950
MxLoopingSmkPresenter::~MxLoopingSmkPresenter()
{
	Destroy(TRUE);
}

// OFFSET: LEGO1 0x100b49b0
void MxLoopingSmkPresenter::Init()
{
	this->m_unk720 = 0;
	this->m_flags &= 0xfd;
	this->m_flags &= 0xfb;
}

// OFFSET: LEGO1 0x100b49d0 STUB
void MxLoopingSmkPresenter::Destroy(MxBool p_fromDestructor)
{
}
