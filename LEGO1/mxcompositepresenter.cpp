#include "mxcompositepresenter.h"

#include "decomp.h"
#include "mxnotificationmanager.h"

DECOMP_SIZE_ASSERT(MxCompositePresenter, 0x4c);

// FUNCTION: LEGO1 0x1000caf0
MxBool MxCompositePresenter::VTable0x64(undefined4 p_unknown)
{
	if (m_compositePresenter)
		return m_compositePresenter->VTable0x64(p_unknown);
	return TRUE;
}

// FUNCTION: LEGO1 0x100b60b0
MxCompositePresenter::MxCompositePresenter()
{
	NotificationManager()->Register(this);
}

// TEMPLATE: LEGO1 0x100b61a0
// list<MxPresenter *,allocator<MxPresenter *> >::~list<MxPresenter *,allocator<MxPresenter *> >

// FUNCTION: LEGO1 0x100b6210
// MxCompositePresenter::ClassName

// FUNCTION: LEGO1 0x100b6220
// MxCompositePresenter::IsA

// SYNTHETIC: LEGO1 0x100b62d0
// MxCompositePresenter::`scalar deleting destructor'

// FUNCTION: LEGO1 0x100b62f0
// MxCompositePresenterList::~MxCompositePresenterList

// TEMPLATE: LEGO1 0x100b6340
// List<MxPresenter *>::~List<MxPresenter *>

// FUNCTION: LEGO1 0x100b6390
MxCompositePresenter::~MxCompositePresenter()
{
	NotificationManager()->Unregister(this);
}

// STUB: LEGO1 0x100b6410
MxResult MxCompositePresenter::StartAction(MxStreamController*, MxDSAction*)
{
	// TODO
	return SUCCESS;
}

// STUB: LEGO1 0x100b65e0
void MxCompositePresenter::EndAction()
{
	// TODO
}

// STUB: LEGO1 0x100b6760
MxLong MxCompositePresenter::Notify(MxParam& p)
{
	// TODO
	return 0;
}

// STUB: LEGO1 0x100b67f0
void MxCompositePresenter::VTable0x58()
{
	// TODO
}

// STUB: LEGO1 0x100b69b0
void MxCompositePresenter::VTable0x5c()
{
	// TODO
}

// FUNCTION: LEGO1 0x100b6b40
void MxCompositePresenter::VTable0x60(MxPresenter* p_presenter)
{
	for (MxCompositePresenterList::iterator it = m_list.begin(); it != m_list.end(); it++) {
		if (*it == p_presenter) {
			if (++it == m_list.end()) {
				if (m_compositePresenter)
					m_compositePresenter->VTable0x60(this);
			}
			else if (m_action->IsA("MxDSSerialAction")) {
				MxPresenter* presenter = *it;
				if (presenter->GetCurrentTickleState() == TickleState_Idle)
					presenter->SetTickleState(TickleState_Ready);
			}
			return;
		}
	}
}

// STUB: LEGO1 0x100b6bc0
void MxCompositePresenter::SetTickleState(TickleState p_tickleState)
{
	// TODO
}

// STUB: LEGO1 0x100b6c30
void MxCompositePresenter::Enable(MxBool p_enable)
{
	// TODO
}

// STUB: LEGO1 0x100b6c80
MxBool MxCompositePresenter::HasTickleStatePassed(TickleState p_tickleState)
{
	// TODO
	return TRUE;
}
