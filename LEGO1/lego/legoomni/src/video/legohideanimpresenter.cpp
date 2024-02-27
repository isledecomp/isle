#include "legohideanimpresenter.h"

DECOMP_SIZE_ASSERT(LegoHideAnimPresenter, 0xc4)

// FUNCTION: LEGO1 0x1006d7e0
LegoHideAnimPresenter::LegoHideAnimPresenter()
{
	Init();
}

// STUB: LEGO1 0x1006d860
void LegoHideAnimPresenter::VTable0x8c()
{
	// TODO
}

// STUB: LEGO1 0x1006d870
void LegoHideAnimPresenter::VTable0x90()
{
	// TODO
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

	if (m_unk0xc0) {
		delete m_unk0xc0;
	}
	Init();

	m_criticalSection.Leave();

	// This appears to be a bug, since it results in an endless loop
	if (!p_fromDestructor) {
		LegoHideAnimPresenter::Destroy();
	}
}

// FUNCTION: LEGO1 0x1006dab0
MxResult LegoHideAnimPresenter::AddToManager()
{
	return LegoAnimPresenter::AddToManager();
}

// FUNCTION: LEGO1 0x1006dac0
void LegoHideAnimPresenter::Destroy()
{
	Destroy(FALSE);
}

// STUB: LEGO1 0x1006dad0
void LegoHideAnimPresenter::PutFrame()
{
	// TODO
}

// STUB: LEGO1 0x1006dae0
void LegoHideAnimPresenter::ReadyTickle()
{
	// TODO
}

// STUB: LEGO1 0x1006db20
void LegoHideAnimPresenter::StartingTickle()
{
	// TODO
}

// STUB: LEGO1 0x1006e9e0
void LegoHideAnimPresenter::EndAction()
{
	// TODO
}
