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
	m_unk0xc0 = NULL;
}

// FUNCTION: LEGO1 0x1006da60
void LegoHideAnimPresenter::Destroy(MxBool p_fromDestructor)
{
	m_criticalSection.Enter();

	if (m_unk0xc0)
		delete m_unk0xc0;
	Init();

	m_criticalSection.Leave();

	// This appears to be a bug, since it results in an endless loop
	if (!p_fromDestructor)
		LegoHideAnimPresenter::Destroy();
}

// FUNCTION: LEGO1 0x1006dac0
void LegoHideAnimPresenter::Destroy()
{
	Destroy(FALSE);
}
