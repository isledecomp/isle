#include "mxcontrolpresenter.h"

#include "mxticklemanager.h"
#include "mxutil.h"

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
void MxControlPresenter::VTable0x68(MxBool p_unk0x50)
{
	m_unk0x50 = p_unk0x50;
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

// FUNCTION: LEGO1 0x10044190
MxResult MxControlPresenter::StartAction(MxStreamController* p_controller, MxDSAction* p_action)
{
	MxResult result = MxCompositePresenter::StartAction(p_controller, p_action);

	FUN_100b7220(m_action, MxDSAction::Flag_World | MxDSAction::Flag_Looping, TRUE);
	ParseExtra();

	MxS16 i = 0;
	for (MxCompositePresenterList::iterator it = m_list.begin(); it != m_list.end(); it++) {
		(*it)->Enable((m_unk0x4c != 3 || m_unk0x4e) && IsEnabled() ? m_unk0x4e == i : FALSE);
		i++;
	}

	if (m_unk0x4c == 3) {
		MxDSAction* action = (*m_list.begin())->GetAction();
		action->SetFlags(action->GetFlags() | MxDSAction::Flag_Bit11);
	}

	TickleManager()->RegisterClient(this, 200);

	return result;
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
void MxControlPresenter::VTable0x6c(undefined4)
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

// FUNCTION: LEGO1 0x10044820
void MxControlPresenter::Enable(MxBool p_enable)
{
	if (MxPresenter::IsEnabled() != p_enable) {
		MxPresenter::Enable(p_enable);

		MxS16 i = 0;
		for (MxCompositePresenterList::iterator it = m_list.begin(); it != m_list.end(); it++) {
			if (i == m_unk0x4e) {
				(*it)->Enable((m_unk0x4c != 3 || i != 0) ? p_enable : 0);
				break;
			}

			i++;
		}

		if (!p_enable) {
			m_unk0x4e = 0;
		}
	}
}

// FUNCTION: LEGO1 0x100448a0
MxBool MxControlPresenter::HasTickleStatePassed(TickleState p_tickleState)
{
	MxCompositePresenterList::iterator it = m_list.begin();
	for (MxS16 i = m_unk0x4e; i > 0; i--, it++)
		;

	return (*it)->HasTickleStatePassed(p_tickleState);
}
