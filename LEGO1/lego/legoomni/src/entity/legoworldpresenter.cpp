#include "legoworldpresenter.h"

#include "define.h"
#include "legoanimationmanager.h"
#include "legobuildingmanager.h"
#include "legoentity.h"
#include "legoomni.h"
#include "legoplantmanager.h"
#include "legovideomanager.h"
#include "legoworld.h"
#include "mxactionnotificationparam.h"
#include "mxautolocker.h"
#include "mxdsactionlist.h"
#include "mxdsmediaaction.h"
#include "mxdsmultiaction.h"
#include "mxnotificationmanager.h"
#include "mxobjectfactory.h"
#include "mxpresenter.h"
#include "mxstl/stlcompat.h"
#include "mxutil.h"

// GLOBAL: LEGO1 0x100f75d4
undefined4 g_legoWorldPresenterQuality = 1;

// FUNCTION: LEGO1 0x100665b0
void LegoWorldPresenter::configureLegoWorldPresenter(MxS32 p_legoWorldPresenterQuality)
{
	g_legoWorldPresenterQuality = p_legoWorldPresenterQuality;
}

// FUNCTION: LEGO1 0x100665c0
LegoWorldPresenter::LegoWorldPresenter()
{
	m_unk0x50 = 50000;
}

// FUNCTION: LEGO1 0x10066770
LegoWorldPresenter::~LegoWorldPresenter()
{
	MxBool result = FALSE;
	if (m_entity) {
		MxS32 scriptIndex = ((LegoWorld*) m_entity)->GetScriptIndex();
		PlantManager()->FUN_10026360(scriptIndex);
		AnimationManager()->FUN_1005f720(scriptIndex);
		BuildingManager()->FUN_1002fa00();
		result = ((LegoWorld*) m_entity)->VTable0x5c();
	}

	if (result == FALSE) {
		FUN_10015820(FALSE, LegoOmni::c_disableInput | LegoOmni::c_disable3d | LegoOmni::c_clearScreen);
	}

	if (m_entity) {
#ifdef COMPAT_MODE
		{
			MxNotificationParam param(c_notificationNewPresenter, NULL);
			NotificationManager()->Send(m_entity, &param);
		}
#else
		NotificationManager()->Send(m_entity, &MxNotificationParam(c_notificationNewPresenter, NULL));
#endif
	}
}

// FUNCTION: LEGO1 0x10066870
MxResult LegoWorldPresenter::StartAction(MxStreamController* p_controller, MxDSAction* p_action)
{
	MxAutoLocker lock(&m_criticalSection);

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
					presenter->SetTickleState(e_idle);
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

		VideoManager()->RegisterPresenter(*this);

		result = SUCCESS;
	}

	return result;
}

// FUNCTION: LEGO1 0x10066a50
void LegoWorldPresenter::ReadyTickle()
{
	m_entity = (LegoEntity*) MxPresenter::CreateEntity("LegoWorld");
	if (m_entity) {
		m_entity->Create(*m_action);
		Lego()->AddWorld((LegoWorld*) m_entity);
		SetEntityLocation(m_action->GetLocation(), m_action->GetDirection(), m_action->GetUp());
	}

	ParseExtra();
	ProgressTickleState(e_starting);
}

// FUNCTION: LEGO1 0x10066ac0
void LegoWorldPresenter::StartingTickle()
{
	if (m_action->IsA("MxDSSerialAction")) {
		MxPresenter* presenter = *m_list.begin();
		if (presenter->GetCurrentTickleState() == e_idle) {
			presenter->SetTickleState(e_ready);
		}
	}
	else {
		for (MxCompositePresenterList::iterator it = m_list.begin(); it != m_list.end(); it++) {
			if ((*it)->GetCurrentTickleState() == e_idle) {
				(*it)->SetTickleState(e_ready);
			}
		}
	}

	ProgressTickleState(e_streaming);
}

// STUB: LEGO1 0x10066b40
void LegoWorldPresenter::LoadWorld(char* p_worldName, LegoWorld* p_world)
{
}

// FUNCTION: LEGO1 0x10067a70
void LegoWorldPresenter::VTable0x60(MxPresenter* p_presenter)
{
	MxCompositePresenter::VTable0x60(p_presenter);
	MxDSAction* action = p_presenter->GetAction();

	if (action->GetDuration() != -1 && (action->GetFlags() & MxDSAction::c_looping) == 0) {
		if (!action->IsA("MxDSMediaAction")) {
			return;
		}

		if (((MxDSMediaAction*) action)->GetSustainTime() != -1) {
			return;
		}
	}

	if (!p_presenter->IsA("LegoAnimPresenter") && !p_presenter->IsA("MxControlPresenter") &&
		!p_presenter->IsA("MxCompositePresenter")) {
		p_presenter->SendToCompositePresenter(Lego());
		((LegoWorld*) m_entity)->Add(p_presenter);
	}
}

// FUNCTION: LEGO1 0x10067b00
void LegoWorldPresenter::ParseExtra()
{
	MxU16 extraLength;
	char* extraData;
	m_action->GetExtra(extraLength, extraData);

	if (extraLength & MAXWORD) {
		char extraCopy[1024];
		memcpy(extraCopy, extraData, extraLength & MAXWORD);
		extraCopy[extraLength & MAXWORD] = '\0';

		char output[1024];
		if (KeyValueStringParse(output, g_strWORLD, extraCopy)) {
			char* worldKey = strtok(output, g_parseExtraTokens);
			LoadWorld(worldKey, (LegoWorld*) m_entity);
			((LegoWorld*) m_entity)->SetScriptIndex(Lego()->GetScriptIndex(worldKey));
		}
	}
}
