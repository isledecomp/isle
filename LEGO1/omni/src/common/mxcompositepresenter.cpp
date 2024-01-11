#include "mxcompositepresenter.h"

#include "decomp.h"
#include "mxautolocker.h"
#include "mxdsmultiaction.h"
#include "mxnotificationmanager.h"
#include "mxobjectfactory.h"

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
MxResult MxCompositePresenter::StartAction(MxStreamController* p_controller, MxDSAction* p_action)
{
	MxAutoLocker lock(&m_criticalSection);

	MxResult result = FAILURE;
	MxDSActionList* actions = ((MxDSMultiAction*) p_action)->GetActionList();
	MxObjectFactory* factory = ObjectFactory();
	MxDSActionListCursor cursor(actions);
	MxDSAction* action;

	if (MxPresenter::StartAction(p_controller, p_action) == SUCCESS) {
		// The usual cursor.Next() loop doesn't match here, even though
		// the logic is the same. It does match when "deconstructed" into
		// the following Head(), Current() and NextFragment() calls,
		// but this seems unlikely to be the original code.
		// The alpha debug build also uses Next().
		cursor.Head();
		while (cursor.Current(action)) {
			cursor.NextFragment();

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

	((MxDSMultiAction*) m_action)->GetActionList()->DeleteAll(FALSE);

	while (!m_list.empty()) {
		MxPresenter* presenter = m_list.front();
		m_list.pop_front();
		presenter->SetCompositePresenter(NULL);
		presenter->EndAction();
	}

	MxDSAction* action = m_action;
	MxPresenter::EndAction();

	if (action && action->GetOrigin()) {
#ifdef COMPAT_MODE
		{
			MxEndActionNotificationParam param(c_notificationEndAction, this, action, FALSE);
			NotificationManager()->Send(action->GetOrigin(), &param);
		}
#else
		NotificationManager()->Send(
			action->GetOrigin(),
			&MxEndActionNotificationParam(c_notificationEndAction, this, action, FALSE)
		);
#endif
	}
}

// FUNCTION: LEGO1 0x100b6760
MxLong MxCompositePresenter::Notify(MxParam& p_param)
{
	MxAutoLocker lock(&m_criticalSection);

	switch (((MxNotificationParam&) p_param).GetNotification()) {
	case c_notificationEndAction:
		VTable0x58((MxEndActionNotificationParam&) p_param);
		break;
	case MXPRESENTER_NOTIFICATION:
		VTable0x5c((MxNotificationParam&) p_param);
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

		if (cursor.Find(action))
			cursor.Detach();
	}

	if (presenter)
		delete presenter;

	if (action)
		delete action;

	if (m_list.empty()) {
		EndAction();
	}
	else {
		if (m_action->IsA("MxDSSerialAction") && it != m_list.end()) {
			MxPresenter* presenter = *it;
			if (presenter->GetCurrentTickleState() == TickleState_Idle)
				presenter->SetTickleState(TickleState_Ready);
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

				if (presenter->GetCurrentTickleState() == TickleState_Idle)
					presenter->SetTickleState(TickleState_Ready);

				MxDSActionList* actions = ((MxDSMultiAction*) m_action)->GetActionList();
				MxDSActionListCursor cursor(actions);

				if (cursor.Find(presenter->GetAction()))
					cursor.Detach();

				if (m_list.empty()) {
					EndAction();
				}
				else {
					if (m_action->IsA("MxDSSerialAction")) {
						MxPresenter* presenter = *it;
						if (presenter->GetCurrentTickleState() == TickleState_Idle)
							presenter->SetTickleState(TickleState_Ready);
					}
				}

				return;
			}
		}

		NotificationManager()->Send(this, &p_param);
	}
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

// FUNCTION: LEGO1 0x100b6bc0
void MxCompositePresenter::SetTickleState(TickleState p_tickleState)
{
	ProgressTickleState(p_tickleState);

	for (MxCompositePresenterList::iterator it = m_list.begin(); it != m_list.end(); it++) {
		MxPresenter* presenter = *it;
		presenter->SetTickleState(p_tickleState);

		if (m_action->IsA("MxDSSerialAction") && p_tickleState == TickleState_Ready)
			return;
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
		if (!presenter->HasTickleStatePassed(p_tickleState))
			return FALSE;
	}

	return TRUE;
}
