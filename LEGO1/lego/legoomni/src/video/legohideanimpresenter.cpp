#include "legohideanimpresenter.h"

#include "legomain.h"
#include "legoworld.h"
#include "misc.h"

DECOMP_SIZE_ASSERT(LegoHideAnimPresenter, 0xc4)

// FUNCTION: LEGO1 0x1006d7e0
LegoHideAnimPresenter::LegoHideAnimPresenter()
{
	Init();
}

// FUNCTION: LEGO1 0x1006d860
void LegoHideAnimPresenter::VTable0x8c()
{
}

// FUNCTION: LEGO1 0x1006d870
void LegoHideAnimPresenter::VTable0x90()
{
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

// FUNCTION: LEGO1 0x1006dad0
void LegoHideAnimPresenter::PutFrame()
{
}

// FUNCTION: LEGO1 0x1006dae0
// FUNCTION: BETA10 0x100530f4
void LegoHideAnimPresenter::ReadyTickle()
{
	LegoLoopingAnimPresenter::ReadyTickle();

	if (m_currentWorld) {
		if (m_currentTickleState == e_starting && m_compositePresenter != NULL) {
			SendToCompositePresenter(Lego());
		}

		m_currentWorld->Add(this);
	}
}

// FUNCTION: LEGO1 0x1006db20
// FUNCTION: BETA10 0x1005316b
void LegoHideAnimPresenter::StartingTickle()
{
	LegoLoopingAnimPresenter::StartingTickle();

	if (m_currentTickleState == e_streaming) {
		FUN_1006dc10();
		FUN_1006db40(0);
	}
}

// STUB: LEGO1 0x1006db40
// FUNCTION: BETA10 0x100531ab
void LegoHideAnimPresenter::FUN_1006db40(undefined4)
{
	// TODO
}

// STUB: LEGO1 0x1006dc10
// FUNCTION: BETA10 0x100532fd
void LegoHideAnimPresenter::FUN_1006dc10()
{
	// TODO
}

// FUNCTION: LEGO1 0x1006e9e0
// FUNCTION: BETA10 0x100535ef
void LegoHideAnimPresenter::EndAction()
{
	if (m_action) {
		MxVideoPresenter::EndAction();

		if (m_currentWorld) {
			m_currentWorld->Remove(this);
		}
	}
}
