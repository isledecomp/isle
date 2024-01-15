#include "legoworldpresenter.h"

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
#include "mxdsmultiaction.h"
#include "mxnotificationmanager.h"
#include "mxobjectfactory.h"
#include "mxpresenter.h"
#include "mxstl/stlcompat.h"

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
		undefined4 world = ((LegoWorld*) m_entity)->GetUnknown0xec();
		PlantManager()->FUN_10026360(world);
		AnimationManager()->FUN_1005f720(world);
		BuildingManager()->FUN_1002fa00();
		result = ((LegoWorld*) m_entity)->VTable0x5c();
	}

	if (result == FALSE) {
		FUN_10015820(0, 7);
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
				if (presenter->StartAction(p_controller, action) == SUCCESS) {
					presenter->SetTickleState(TickleState_Idle);
					success = TRUE;
				}
			}

			if (success) {
				action->SetOrigin(this);
				m_list.push_back(presenter);
			}
			else if (presenter)
				delete presenter;
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
	ProgressTickleState(TickleState_Starting);
}

// FUNCTION: LEGO1 0x10066ac0
void LegoWorldPresenter::StartingTickle()
{
	if (m_action->IsA("MxDSSerialAction")) {
		MxPresenter* presenter = *m_list.begin();
		if (presenter->GetCurrentTickleState() == TickleState_Idle) {
			presenter->SetTickleState(TickleState_Ready);
		}
	}
	else {
		for (MxCompositePresenterList::iterator it = m_list.begin(); it != m_list.end(); it++) {
			if ((*it)->GetCurrentTickleState() == TickleState_Idle) {
				(*it)->SetTickleState(TickleState_Ready);
			}
		}
	}

	ProgressTickleState(TickleState_Streaming);
}

// STUB: LEGO1 0x10067a70
void LegoWorldPresenter::VTable0x60(MxPresenter* p_presenter)
{
}

// STUB: LEGO1 0x10067b00
void LegoWorldPresenter::ParseExtra()
{
}
