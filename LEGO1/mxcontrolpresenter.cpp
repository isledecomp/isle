#include "mxcontrolpresenter.h"

#include "legoomni.h"
#include "mxticklemanager.h"

DECOMP_SIZE_ASSERT(MxControlPresenter, 0x5c)

// FUNCTION: LEGO1 0x10043f50
MxControlPresenter::MxControlPresenter()
{
	this->m_unk0x4c = 0;
	this->m_unk0x4e = -1;
	this->m_unk0x50 = 0;
	this->m_unk0x52 = 0;
	this->m_unk0x58 = 0;
	this->m_unk0x54 = 0;
}

// FUNCTION: LEGO1 0x10043fd0
void MxControlPresenter::RepeatingTickle()
{
	// Intentionally empty
}

// FUNCTION: LEGO1 0x10043fe0
MxBool MxControlPresenter::VTable0x64(undefined4 p_undefined)
{
	return this->m_unk0x50;
}

// FUNCTION: LEGO1 0x10043ff0
void MxControlPresenter::VTable0x68(undefined p_undefined)
{
	this->m_unk0x50 = p_undefined;
}

// FUNCTION: LEGO1 0x10044110
MxControlPresenter::~MxControlPresenter()
{
	if (this->m_unk0x58) {
		delete this->m_unk0x58;
	}
}

// FUNCTION: LEGO1 0x10044180
MxResult MxControlPresenter::AddToManager()
{
	this->m_unk0x4e = 0;
	return SUCCESS;
}

// STUB: LEGO1 0x10044190
MxResult MxControlPresenter::StartAction(MxStreamController* p_controller, MxDSAction* p_action)
{
	// TODO
	return FAILURE;
}

// FUNCTION: LEGO1 0x10044610
void MxControlPresenter::ReadyTickle()
{
	MxPresenter::ParseExtra();
	TickleManager()->UnregisterClient(this);

	m_previousTickleStates |= 1 << (unsigned char) m_currentTickleState;
	m_currentTickleState = TickleState_Repeating;
}

// STUB: LEGO1 0x10044540
void MxControlPresenter::VTable0x6C(undefined2 p_undefined)
{
	// TODO
}

// STUB: LEGO1 0x10044640
void MxControlPresenter::ParseExtra()
{
	// TODO
}

// STUB: LEGO1 0x10044820
void MxControlPresenter::Enable(MxBool p_enable)
{
	// TODO
}

// STUB: LEGO1 0x100448a0
MxBool MxControlPresenter::HasTickleStatePassed(TickleState p_tickleState)
{
	// TODO
	return FALSE;
}