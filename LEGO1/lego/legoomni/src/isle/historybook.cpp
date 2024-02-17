#include "historybook.h"

#include "legocontrolmanager.h"
#include "legoinputmanager.h"
#include "legoomni.h"
#include "mxnotificationmanager.h"
#include "mxomni.h"
#include "mxtransitionmanager.h"

DECOMP_SIZE_ASSERT(HistoryBook, 0x3e4)

// FUNCTION: LEGO1 0x100822f0
HistoryBook::HistoryBook()
{
	memset(m_unk0xfc, NULL, sizeof(m_unk0xfc));
	memset(m_unk0x164, NULL, sizeof(m_unk0x164));
	memset(m_unk0x394, NULL, sizeof(m_unk0x394));
	NotificationManager()->Register(this);
}

// STUB: LEGO1 0x100824d0
HistoryBook::~HistoryBook()
{
	// TODO
}

// FUNCTION: LEGO1 0x10082610
MxResult HistoryBook::Create(MxDSAction& p_dsAction)
{
	MxResult result = LegoWorld::Create(p_dsAction);
	if (result == SUCCESS) {
		InputManager()->SetWorld(this);
		ControlManager()->Register(this);
	}

	InputManager()->SetCamera(NULL);
	InputManager()->Register(this);

	GameState()->SetCurrentArea(LegoGameState::Area::e_histbook);
	GameState()->StopArea(LegoGameState::Area::e_previousArea);
	return result;
}

// FUNCTION: LEGO1 0x10082680
MxLong HistoryBook::Notify(MxParam& p_param)
{
	LegoWorld::Notify(p_param);
	if (m_worldStarted) {
		switch (((MxNotificationParam&) p_param).GetNotification()) {
		case c_notificationButtonUp:
			m_transitionDestination = LegoGameState::Area::e_infoscor;
			TransitionManager()->StartTransition(MxTransitionManager::TransitionType::e_pixelation, 50, FALSE, FALSE);
			break;
		case c_notificationTransitioned:
			GameState()->SwitchArea(m_transitionDestination);
			break;
		}
	}

	return 0;
}

// STUB: LEGO1 0x100826f0
void HistoryBook::ReadyWorld()
{
	// TODO
}

// FUNCTION: LEGO1 0x10082a10
MxBool HistoryBook::VTable0x64()
{
	m_transitionDestination = LegoGameState::Area::e_infomain;
	return TRUE;
}
