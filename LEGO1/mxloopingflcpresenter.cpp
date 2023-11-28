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
	this->m_unk68 = 0;
	this->m_flags &= 0xfd;
	this->m_flags &= 0xfb;
}

// FUNCTION: LEGO1 0x100b4432 STUB
void MxLoopingFlcPresenter::Destroy(MxBool p_fromDestructor)
{
	// TODO
}
