#include "legohideanimpresenter.h"

DECOMP_SIZE_ASSERT(LegoHideAnimPresenter, 0xc4)

// FUNCTION: LEGO1 0x1006d7e0
LegoHideAnimPresenter::LegoHideAnimPresenter()
{
	Init();
}

// FUNCTION: LEGO1 0x1006d9f0
LegoHideAnimPresenter::~LegoHideAnimPresenter()
{
	Destroy(TRUE);
}

// FUNCTION: LEGO1 0x1006da50
void LegoHideAnimPresenter::Init()
{
	this->m_unk0xc0 = NULL;
}

// STUB: LEGO1 0x1006da60
void LegoHideAnimPresenter::Destroy(MxBool p_fromDestructor)
{
	m_criticalSection.Enter();
	if (!this->m_unk0xc0)
		delete this->m_unk0xc0;
	Init();
	m_criticalSection.Leave();

	// if (!p_fromDestructor)
	// TODO: another function
}
