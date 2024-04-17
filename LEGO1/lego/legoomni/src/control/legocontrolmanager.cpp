#include "legocontrolmanager.h"

#include "legoeventnotificationparam.h"
#include "legovideomanager.h"
#include "misc.h"
#include "mxcontrolpresenter.h"
#include "mxmisc.h"
#include "mxpresenter.h"
#include "mxticklemanager.h"

DECOMP_SIZE_ASSERT(LegoControlManager, 0x60)
DECOMP_SIZE_ASSERT(LegoControlManagerEvent, 0x2c)

// FUNCTION: LEGO1 0x10028520
LegoControlManager::LegoControlManager()
{
	m_presenterList = NULL;
	m_unk0x08 = 0;
	m_unk0x0c = 0;
	m_unk0x10 = FALSE;
	m_unk0x14 = NULL;
	TickleManager()->RegisterClient(this, 10);
}

// FUNCTION: LEGO1 0x10028d60
LegoControlManager::~LegoControlManager()
{
	TickleManager()->UnregisterClient(this);
}

// FUNCTION: LEGO1 0x10028df0
void LegoControlManager::FUN_10028df0(MxPresenterList* p_presenterList)
{
	m_presenterList = p_presenterList;
	g_unk0x100f31b0 = -1;
	g_unk0x100f31b4 = NULL;
}

// FUNCTION: LEGO1 0x10028e10
void LegoControlManager::Register(MxCore* p_listener)
{
	m_notifyList.Append(p_listener);
}

// FUNCTION: LEGO1 0x10028ea0
void LegoControlManager::Unregister(MxCore* p_listener)
{
	LegoNotifyListCursor cursor(&m_notifyList);
	if (cursor.Find(p_listener)) {
		cursor.Detach();
	}
}

// FUNCTION: LEGO1 0x10029210
MxBool LegoControlManager::FUN_10029210(LegoEventNotificationParam& p_param, MxPresenter* p_presenter)
{
	if (m_presenterList != NULL && m_presenterList->GetCount() != 0) {
		m_unk0x14 = p_presenter;

		if (p_param.GetType() == c_notificationButtonUp || p_param.GetType() == c_notificationButtonDown) {
			m_event.SetType(p_param.GetType());
			m_event.SetSender(p_param.GetSender());
			m_event.SetModifier(p_param.GetModifier());
			m_event.SetX(p_param.GetX());
			m_event.SetY(p_param.GetY());
			m_event.SetKey(p_param.GetKey());

			if (p_param.GetType() == c_notificationButtonUp) {
				if (m_unk0x10 == TRUE) {
					m_unk0x10 = FALSE;
					return TRUE;
				}

				if (g_unk0x100f31b0 != -1 && g_unk0x100f31b4 != NULL) {
					if (m_unk0x08 == 2) {
						return FUN_10029750();
					}
					else {
						m_unk0x0c = 1;
						return TRUE;
					}
				}
			}
			else if (p_param.GetType() == c_notificationButtonDown) {
				if (m_unk0x0c == 1) {
					m_unk0x10 = TRUE;
					return TRUE;
				}
				else {
					return FUN_10029630();
				}
			}
		}

		return FALSE;
	}
	else {
		g_unk0x100f31b0 = -1;
		g_unk0x100f31b4 = NULL;

		return FALSE;
	}
}

// FUNCTION: LEGO1 0x100292e0
void LegoControlManager::FUN_100292e0()
{
	LegoNotifyListCursor cursor(&m_notifyList);
	MxCore* target;

	cursor.Head();
	while (cursor.Current(target)) {
		cursor.Next();
		target->Notify(m_event);
	}
}

// STUB: LEGO1 0x100293c0
void LegoControlManager::FUN_100293c0(undefined4, const char*, undefined2)
{
}

// FUNCTION: LEGO1 0x100294e0
MxControlPresenter* LegoControlManager::FUN_100294e0(MxS32 p_x, MxS32 p_y)
{
	if (m_presenterList) {
		MxPresenterListCursor cursor(m_presenterList);
		MxPresenter* control;
		MxVideoPresenter* presenter = (MxVideoPresenter*) VideoManager()->GetPresenterAt(p_x, p_y);

		if (presenter) {
			while (cursor.Next(control)) {
				if (((MxControlPresenter*) control)->FUN_10044270(p_x, p_y, presenter)) {
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
	if (m_unk0x08 == 2 && m_unk0x0c == 1) {
		m_event.SetType(c_notificationButtonUp);
		FUN_10029750();
		return 0;
	}
	else if (m_unk0x08 == 1) {
		m_unk0x08 = 2;
	}
	return 0;
}

// FUNCTION: LEGO1 0x10029630
MxBool LegoControlManager::FUN_10029630()
{
	MxPresenterListCursor cursor(m_presenterList);
	MxPresenter* presenter;

	while (cursor.Next(presenter)) {
		if (((MxControlPresenter*) presenter)->FUN_10044480(&m_event, m_unk0x14)) {
			g_unk0x100f31b0 = m_event.GetClickedObjectId();
			g_unk0x100f31b4 = m_event.GetClickedAtom();
			FUN_100292e0();
			m_unk0x08 = 1;
			return TRUE;
		}
	}

	return FALSE;
}

// FUNCTION: LEGO1 0x10029750
MxBool LegoControlManager::FUN_10029750()
{
	MxPresenterListCursor cursor(m_presenterList);
	MxPresenter* presenter;

	while (cursor.Next(presenter)) {
		if (presenter->GetAction() && presenter->GetAction()->GetObjectId() == g_unk0x100f31b0 &&
			presenter->GetAction()->GetAtomId().GetInternal() == g_unk0x100f31b4) {
			if (((MxControlPresenter*) presenter)->FUN_10044480(&m_event, m_unk0x14)) {
				FUN_100292e0();
			}

			g_unk0x100f31b0 = -1;
			g_unk0x100f31b4 = NULL;

			m_unk0x08 = 0;
			m_unk0x0c = 0;

			return TRUE;
		}
	}

	g_unk0x100f31b0 = -1;
	g_unk0x100f31b4 = NULL;
	return FALSE;
}
