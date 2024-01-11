#include "mxcontrolpresenter.h"

#include "mxticklemanager.h"

DECOMP_SIZE_ASSERT(MxControlPresenter, 0x5c)

// FUNCTION: LEGO1 0x10043f50
MxControlPresenter::MxControlPresenter()
{
	this->m_unk0x4c = 0;
	this->m_unk0x4e = -1;
	this->m_unk0x50 = FALSE;
	this->m_unk0x52 = 0;
	this->m_unk0x58 = 0;
	this->m_unk0x54 = 0;
}

// FUNCTION: LEGO1 0x10043fd0
void MxControlPresenter::RepeatingTickle()
{
	// empty
}

// FUNCTION: LEGO1 0x10043fe0
MxBool MxControlPresenter::VTable0x64(undefined4 p_undefined)
{
	return m_unk0x50;
}

// FUNCTION: LEGO1 0x10043ff0
void MxControlPresenter::VTable0x68(MxBool p_undefined)
{
	m_unk0x50 = p_undefined;
}

// FUNCTION: LEGO1 0x10044110
MxControlPresenter::~MxControlPresenter()
{
	if (m_unk0x58)
		delete m_unk0x58;
}

// FUNCTION: LEGO1 0x10044180
MxResult MxControlPresenter::AddToManager()
{
	m_unk0x4e = 0;
	return SUCCESS;
}

// STUB: LEGO1 0x10044190
MxResult MxControlPresenter::StartAction(MxStreamController*, MxDSAction*)
{
	// TODO
	return SUCCESS;
}

// FUNCTION: LEGO1 0x10044260
void MxControlPresenter::EndAction()
{
	if (m_action) {
		m_unk0x50 = TRUE;
		MxCompositePresenter::EndAction();
	}
}

// STUB: LEGO1 0x10044270
MxBool MxControlPresenter::FUN_10044270(undefined4, undefined4, undefined4*)
{
	// TODO
	return TRUE;
}

// STUB: LEGO1 0x10044480
MxBool MxControlPresenter::FUN_10044480(undefined4, undefined4*)
{
	// TODO
	return TRUE;
}

// STUB: LEGO1 0x10044540
void MxControlPresenter::FUN_10044540(undefined2)
{
	// TODO
}

// FUNCTION: LEGO1 0x10044610
void MxControlPresenter::ReadyTickle()
{
	MxPresenter::ParseExtra();
	TickleManager()->UnregisterClient(this);
	ProgressTickleState(TickleState_Repeating);
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
	return TRUE;
}
