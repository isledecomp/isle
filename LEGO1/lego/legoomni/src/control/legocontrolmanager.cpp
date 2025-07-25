#include "legocontrolmanager.h"

#include "legoeventnotificationparam.h"
#include "legovideomanager.h"
#include "misc.h"
#include "mxcontrolpresenter.h"
#include "mxdsaction.h"
#include "mxmisc.h"
#include "mxpresenter.h"
#include "mxticklemanager.h"

DECOMP_SIZE_ASSERT(LegoControlManager, 0x60)
DECOMP_SIZE_ASSERT(LegoControlManagerNotificationParam, 0x2c)
DECOMP_SIZE_ASSERT(LegoEventNotificationParam, 0x20)

// FUNCTION: LEGO1 0x10028520
// STUB: BETA10 0x1008ae50
LegoControlManager::LegoControlManager()
{
	m_presenterList = NULL;
	m_buttonDownState = e_idle;
	m_handleUpNextTickle = 0;
	m_secondButtonDown = FALSE;
	m_handledPresenter = NULL;
	TickleManager()->RegisterClient(this, 10);
}

// FUNCTION: LEGO1 0x10028d60
LegoControlManager::~LegoControlManager()
{
	TickleManager()->UnregisterClient(this);
}

// FUNCTION: LEGO1 0x10028df0
void LegoControlManager::SetPresenterList(MxPresenterList* p_presenterList)
{
	m_presenterList = p_presenterList;
	g_clickedObjectId = -1;
	g_clickedAtom = NULL;
}

// FUNCTION: LEGO1 0x10028e10
// FUNCTION: BETA10 0x1007c232
void LegoControlManager::Register(MxCore* p_listener)
{
	m_notifyList.Append(p_listener);
}

// FUNCTION: LEGO1 0x10028ea0
// FUNCTION: BETA10 0x1007c330
void LegoControlManager::Unregister(MxCore* p_listener)
{
	LegoNotifyListCursor cursor(&m_notifyList);
	if (cursor.Find(p_listener)) {
		cursor.Detach();
	}
}

// FUNCTION: LEGO1 0x10029210
MxBool LegoControlManager::HandleButtonDown(LegoEventNotificationParam& p_param, MxPresenter* p_presenter)
{
	if (m_presenterList != NULL && m_presenterList->GetNumElements() != 0) {
		m_handledPresenter = p_presenter;

		if (p_param.GetNotification() == c_notificationButtonUp ||
			p_param.GetNotification() == c_notificationButtonDown) {
			m_event.SetNotification(p_param.GetNotification());
			m_event.SetSender(p_param.GetSender());
			m_event.SetModifier(p_param.GetModifier());
			m_event.SetX(p_param.GetX());
			m_event.SetY(p_param.GetY());
			m_event.SetKey(p_param.GetKey());

			if (p_param.GetNotification() == c_notificationButtonUp) {
				if (m_secondButtonDown == TRUE) {
					m_secondButtonDown = FALSE;
					return TRUE;
				}

				if (g_clickedObjectId != -1 && g_clickedAtom != NULL) {
					if (m_buttonDownState == e_tickled) {
						return HandleButtonUp();
					}
					else {
						m_handleUpNextTickle = 1;
						return TRUE;
					}
				}
			}
			else if (p_param.GetNotification() == c_notificationButtonDown) {
				if (m_handleUpNextTickle == 1) {
					m_secondButtonDown = TRUE;
					return TRUE;
				}
				else {
					return HandleButtonDown();
				}
			}
		}

		return FALSE;
	}
	else {
		g_clickedObjectId = -1;
		g_clickedAtom = NULL;

		return FALSE;
	}
}

// FUNCTION: LEGO1 0x100292e0
void LegoControlManager::Notify()
{
	LegoNotifyListCursor cursor(&m_notifyList);
	MxCore* target;

	cursor.Head();
	while (cursor.Current(target)) {
		cursor.Next();
		target->Notify(m_event);
	}
}

// FUNCTION: LEGO1 0x100293c0
void LegoControlManager::UpdateEnabledChild(MxU32 p_objectId, const char* p_atom, MxS16 p_enabledChild)
{
	if (m_presenterList) {
		MxPresenterListCursor cursor(m_presenterList);
		MxPresenter* control;

		while (cursor.Next(control)) {
			MxDSAction* action = control->GetAction();

			if (action->GetObjectId() == p_objectId && action->GetAtomId().GetInternal() == p_atom) {
				((MxControlPresenter*) control)->UpdateEnabledChild(p_enabledChild);

				if (((MxControlPresenter*) control)->GetEnabledChild() == 0) {
					g_clickedObjectId = -1;
					g_clickedAtom = NULL;
					break;
				}
			}
		}
	}
}

// FUNCTION: LEGO1 0x100294e0
// FUNCTION: BETA10 0x1007c92f
MxControlPresenter* LegoControlManager::GetControlAt(MxS32 p_x, MxS32 p_y)
{
	if (m_presenterList) {
		MxPresenterListCursor cursor(m_presenterList);
		MxPresenter* control;
		MxPresenter* presenter = VideoManager()->GetPresenterAt(p_x, p_y);

		if (presenter) {
			while (cursor.Next(control)) {
				if (((MxControlPresenter*) control)->CheckButtonDown(p_x, p_y, presenter)) {
					return (MxControlPresenter*) control;
				}
			}
		}
	}

	return NULL;
}

// FUNCTION: LEGO1 0x10029600
MxResult LegoControlManager::Tickle()
{
	if (m_buttonDownState == e_tickled && m_handleUpNextTickle == 1) {
		m_event.SetNotification(c_notificationButtonUp);
		HandleButtonUp();
		return 0;
	}
	else if (m_buttonDownState == e_waitNextTickle) {
		m_buttonDownState = e_tickled;
	}
	return 0;
}

// FUNCTION: LEGO1 0x10029630
MxBool LegoControlManager::HandleButtonDown()
{
	MxPresenterListCursor cursor(m_presenterList);
	MxPresenter* presenter;

	while (cursor.Next(presenter)) {
		if (((MxControlPresenter*) presenter)->Notify(&m_event, m_handledPresenter)) {
			g_clickedObjectId = m_event.m_clickedObjectId;
			g_clickedAtom = m_event.GetClickedAtom();
			Notify();
			m_buttonDownState = e_waitNextTickle;
			return TRUE;
		}
	}

	return FALSE;
}

// FUNCTION: LEGO1 0x10029750
MxBool LegoControlManager::HandleButtonUp()
{
	MxPresenterListCursor cursor(m_presenterList);
	MxPresenter* presenter;

	while (cursor.Next(presenter)) {
		if (presenter->GetAction() && presenter->GetAction()->GetObjectId() == g_clickedObjectId &&
			presenter->GetAction()->GetAtomId().GetInternal() == g_clickedAtom) {
			if (((MxControlPresenter*) presenter)->Notify(&m_event, m_handledPresenter)) {
				Notify();
			}

			g_clickedObjectId = -1;
			g_clickedAtom = NULL;

			m_buttonDownState = e_idle;
			m_handleUpNextTickle = 0;

			return TRUE;
		}
	}

	g_clickedObjectId = -1;
	g_clickedAtom = NULL;
	return FALSE;
}
