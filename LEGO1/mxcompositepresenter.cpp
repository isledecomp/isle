#include "mxcompositepresenter.h"

#include "decomp.h"
#include "mxactionnotificationparam.h"
#include "mxautolocker.h"
#include "mxdsmultiaction.h"
#include "mxnotificationmanager.h"
#include "mxobjectfactory.h"

DECOMP_SIZE_ASSERT(MxCompositePresenter, 0x4c);

// FUNCTION: LEGO1 0x1000caf0
MxBool MxCompositePresenter::VTable0x64(undefined4 p_unknown)
{
	if (m_compositePresenter)
		return m_compositePresenter->VTable0x64(p_unknown);
	return TRUE;
}

// TEMPLATE: LEGO1 0x1004ae90
// list<MxPresenter *,allocator<MxPresenter *> >::_Buynode

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

// FUNCTION: LEGO1 0x100b6410
MxResult MxCompositePresenter::StartAction(MxStreamController* p_controller, MxDSAction* p_action)
{
	MxAutoLocker lock(&m_criticalSection);

	MxResult result = FAILURE;
	MxDSActionList* actions = ((MxDSMultiAction*) p_action)->GetActionList();
	MxObjectFactory* factory = ObjectFactory();
	MxDSActionListCursor cursor(actions);
	MxDSAction* action;

	if (MxPresenter::StartAction(p_controller, p_action) == SUCCESS) {
		while (cursor.Next(action)) {
			MxBool success = FALSE;

			action->CopyFlags(m_action->GetFlags());

			const char* presenterName = PresenterNameDispatch(*action);
			MxPresenter* presenter = (MxPresenter*) factory->Create(presenterName);

			if (presenter && presenter->AddToManager() == SUCCESS) {
				presenter->SetCompositePresenter(this);
				if (presenter->StartAction(p_controller, action) == SUCCESS)
					success = TRUE;
			}

			if (success) {
				action->SetOrigin(this);
				m_list.push_back(presenter);
			}
			else if (presenter)
				delete presenter;
		}

		result = SUCCESS;
	}

	return result;
}

// FUNCTION: LEGO1 0x100b65e0
void MxCompositePresenter::EndAction()
{
	MxAutoLocker lock(&m_criticalSection);

	if (!m_action)
		return;

	((MxDSMultiAction*) m_action)->GetActionList()->ClearAll();

	while (!m_list.empty()) {
		MxPresenter* presenter = m_list.front();
		m_list.pop_front();
		presenter->SetCompositePresenter(NULL);
		presenter->EndAction();
	}

	MxDSAction* action = m_action;
	MxPresenter::EndAction();

	if (action && action->GetOrigin()) {
		NotificationManager()->Send(
			action->GetOrigin(),
			&MxEndActionNotificationParam(c_notificationEndAction, this, action, FALSE)
		);
	}
}

// FUNCTION: LEGO1 0x100b6760
MxLong MxCompositePresenter::Notify(MxParam& p)
{
	MxAutoLocker lock(&m_criticalSection);

	switch (((MxNotificationParam&) p).GetNotification()) {
	case c_notificationEndAction:
		VTable0x58(p);
		break;
	case MXPRESENTER_NOTIFICATION:
		VTable0x5c(p);
	}

	return 0;
}

// STUB: LEGO1 0x100b67f0
void MxCompositePresenter::VTable0x58(MxParam& p)
{
	// TODO
}

// STUB: LEGO1 0x100b69b0
void MxCompositePresenter::VTable0x5c(MxParam& p)
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
