#include "mxcompositepresenter.h"

#include "decomp.h"
#include "mxactionnotificationparam.h"
#include "mxautolock.h"
#include "mxdsmultiaction.h"
#include "mxmisc.h"
#include "mxnotificationmanager.h"
#include "mxobjectfactory.h"

#include <assert.h>

DECOMP_SIZE_ASSERT(MxCompositePresenter, 0x4c);

// FUNCTION: LEGO1 0x100b60b0
MxCompositePresenter::MxCompositePresenter()
{
	NotificationManager()->Register(this);
}

// FUNCTION: LEGO1 0x100b6390
MxCompositePresenter::~MxCompositePresenter()
{
	NotificationManager()->Unregister(this);
}

// FUNCTION: LEGO1 0x100b6410
// FUNCTION: BETA10 0x10137344
MxResult MxCompositePresenter::StartAction(MxStreamController* p_controller, MxDSAction* p_action)
{
	AUTOLOCK(m_criticalSection);

	MxResult result = FAILURE;
	MxDSActionList* actions = ((MxDSMultiAction*) p_action)->GetActionList();
	MxObjectFactory* factory = ObjectFactory();
	MxDSActionListCursor cursor(actions);
	MxDSAction* action;

	if (MxPresenter::StartAction(p_controller, p_action) == SUCCESS) {
		cursor.Head();

		while (cursor.Current(action)) {
			MxBool success = FALSE;
			const char* presenterName;
			MxPresenter* presenter = NULL;

			cursor.Next();

			if (m_action->GetFlags() & MxDSAction::c_looping) {
				action->SetFlags(action->GetFlags() | MxDSAction::c_looping);
			}
			else if (m_action->GetFlags() & MxDSAction::c_bit3) {
				action->SetFlags(action->GetFlags() | MxDSAction::c_bit3);
			}

			presenterName = PresenterNameDispatch(*action);
			presenter = (MxPresenter*) factory->Create(presenterName);

			if (presenter && presenter->AddToManager() == SUCCESS) {
				presenter->SetCompositePresenter(this);
				if (presenter->StartAction(p_controller, action) == SUCCESS) {
					success = TRUE;
				}
			}

			if (success) {
				action->SetOrigin(this);
				m_list.push_back(presenter);
			}
			else if (presenter) {
				delete presenter;
			}
		}

		result = SUCCESS;
	}

	return result;
}

// FUNCTION: LEGO1 0x100b65e0
// FUNCTION: BETA10 0x101375bc
void MxCompositePresenter::EndAction()
{
	AUTOLOCK(m_criticalSection);

	if (!m_action) {
		return;
	}

	((MxDSMultiAction*) m_action)->GetActionList()->Empty();

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
			MxEndActionNotificationParam(c_notificationEndAction, this, action, FALSE)
		);
	}
}

// FUNCTION: LEGO1 0x100b6760
// FUNCTION: BETA10 0x1013771e
MxLong MxCompositePresenter::Notify(MxParam& p_param)
{
	AUTOLOCK(m_criticalSection);
	MxNotificationParam& param = (MxNotificationParam&) p_param;

	switch (param.GetNotification()) {
	case c_notificationEndAction:
		VTable0x58((MxEndActionNotificationParam&) p_param);
		break;
	case c_notificationPresenter:
		VTable0x5c((MxNotificationParam&) p_param);
		break;
	default:
		assert(0);
		break;
	}

	return 0;
}

// FUNCTION: LEGO1 0x100b67f0
void MxCompositePresenter::VTable0x58(MxEndActionNotificationParam& p_param)
{
	MxPresenter* presenter = (MxPresenter*) p_param.GetSender();
	MxDSAction* action = p_param.GetAction();
	MxCompositePresenterList::iterator it;

	if (!m_list.empty()) {
		for (it = m_list.begin(); it != m_list.end(); it++) {
			if (*it == presenter) {
				m_list.erase(it++);
				break;
			}
		}
	}

	if (m_action) {
		MxDSActionList* actions = ((MxDSMultiAction*) m_action)->GetActionList();
		MxDSActionListCursor cursor(actions);

		if (cursor.Find(action)) {
			cursor.Detach();
		}
	}

	if (presenter) {
		delete presenter;
	}

	if (action) {
		delete action;
	}

	if (m_list.empty()) {
		EndAction();
	}
	else {
		if (m_action->IsA("MxDSSerialAction") && it != m_list.end()) {
			MxPresenter* presenter = *it;
			if (presenter->GetCurrentTickleState() == e_idle) {
				presenter->SetTickleState(e_ready);
			}
		}
	}
}

// FUNCTION: LEGO1 0x100b69b0
void MxCompositePresenter::VTable0x5c(MxNotificationParam& p_param)
{
	if (!m_list.empty()) {
		MxPresenter* presenter = (MxPresenter*) p_param.GetSender();

		for (MxCompositePresenterList::iterator it = m_list.begin(); it != m_list.end(); it++) {
			if (*it == presenter) {
				m_list.erase(it++);

				if (presenter->GetCurrentTickleState() == e_idle) {
					presenter->SetTickleState(e_ready);
				}

				MxDSActionList* actions = ((MxDSMultiAction*) m_action)->GetActionList();
				MxDSActionListCursor cursor(actions);

				if (cursor.Find(presenter->GetAction())) {
					cursor.Detach();
				}

				if (m_list.empty()) {
					EndAction();
				}
				else {
					if (m_action->IsA("MxDSSerialAction")) {
						MxPresenter* presenter = *it;
						if (presenter->GetCurrentTickleState() == e_idle) {
							presenter->SetTickleState(e_ready);
						}
					}
				}

				return;
			}
		}

		NotificationManager()->Send(this, p_param);
	}
}

// FUNCTION: LEGO1 0x100b6b40
void MxCompositePresenter::VTable0x60(MxPresenter* p_presenter)
{
	for (MxCompositePresenterList::iterator it = m_list.begin(); it != m_list.end(); it++) {
		if (*it == p_presenter) {
			if (++it == m_list.end()) {
				if (m_compositePresenter) {
					m_compositePresenter->VTable0x60(this);
				}
			}
			else if (m_action->IsA("MxDSSerialAction")) {
				MxPresenter* presenter = *it;
				if (presenter->GetCurrentTickleState() == e_idle) {
					presenter->SetTickleState(e_ready);
				}
			}
			return;
		}
	}
}

// FUNCTION: LEGO1 0x100b6bc0
void MxCompositePresenter::SetTickleState(TickleState p_tickleState)
{
	ProgressTickleState(p_tickleState);

	for (MxCompositePresenterList::iterator it = m_list.begin(); it != m_list.end(); it++) {
		MxPresenter* presenter = *it;
		presenter->SetTickleState(p_tickleState);

		if (m_action->IsA("MxDSSerialAction") && p_tickleState == e_ready) {
			return;
		}
	}
}

// FUNCTION: LEGO1 0x100b6c30
void MxCompositePresenter::Enable(MxBool p_enable)
{
	MxPresenter::Enable(p_enable);

	for (MxCompositePresenterList::iterator it = m_list.begin(); it != m_list.end(); it++) {
		MxPresenter* presenter = *it;
		presenter->Enable(p_enable);
	}
}

// FUNCTION: LEGO1 0x100b6c80
MxBool MxCompositePresenter::HasTickleStatePassed(TickleState p_tickleState)
{
	for (MxCompositePresenterList::iterator it = m_list.begin(); it != m_list.end(); it++) {
		MxPresenter* presenter = *it;
		if (!presenter->HasTickleStatePassed(p_tickleState)) {
			return FALSE;
		}
	}

	return TRUE;
}
