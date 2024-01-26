#include "legoworld.h"

#include "legoanimpresenter.h"
#include "legocontrolmanager.h"
#include "legoinputmanager.h"
#include "legoomni.h"
#include "legoutil.h"
#include "legovideomanager.h"
#include "mxactionnotificationparam.h"
#include "mxnotificationmanager.h"
#include "mxnotificationparam.h"
#include "mxomni.h"
#include "mxticklemanager.h"

DECOMP_SIZE_ASSERT(LegoWorld, 0xf8)
DECOMP_SIZE_ASSERT(LegoEntityList, 0x18)
DECOMP_SIZE_ASSERT(LegoEntityListCursor, 0x10)
DECOMP_SIZE_ASSERT(LegoCacheSoundList, 0x18)
DECOMP_SIZE_ASSERT(LegoCacheSoundListCursor, 0x10)

// FUNCTION: LEGO1 0x1001ca40
LegoWorld::LegoWorld() : m_list0x68(TRUE)
{
	m_unk0xf4 = 4;
	m_cameraController = NULL;
	m_entityList = NULL;
	m_cacheSoundList = NULL;
	m_unk0xa4 = 0; // MxBool?
	m_hideAnimPresenter = NULL;
	m_worldStarted = FALSE;

	NotificationManager()->Register(this);
}

// FUNCTION: LEGO1 0x1001d670
MxBool LegoWorld::VTable0x5c()
{
	return FALSE;
}

// FUNCTION: LEGO1 0x1001d680
MxBool LegoWorld::VTable0x64()
{
	return FALSE;
}

// STUB: LEGO1 0x1001dfa0
LegoWorld::~LegoWorld()
{
	// TODO
}

// FUNCTION: LEGO1 0x1001e0b0
MxResult LegoWorld::Create(MxDSAction& p_dsAction)
{
	MxEntity::Create(p_dsAction);

	m_entityList = new LegoEntityList(TRUE);

	if (!m_entityList)
		return FAILURE;

	m_cacheSoundList = new LegoCacheSoundList(TRUE);

	if (!m_cacheSoundList)
		return FAILURE;

	if (!VTable0x54())
		return FAILURE;

	if (p_dsAction.GetFlags() & MxDSAction::c_enabled) {
		if (GetCurrentWorld()) {
			GetCurrentWorld()->VTable0x68(0);
		}

		SetCurrentWorld(this);
		ControlManager()->FUN_10028df0(&m_controlPresenters);
	}

	SetIsWorldActive(TRUE);
	m_unk0xec = -1;

	return SUCCESS;
}

// STUB: LEGO1 0x1001e9d0
void LegoWorld::Destroy(MxBool p_fromDestructor)
{
	// TODO
}

// FUNCTION: LEGO1 0x1001f5e0
MxLong LegoWorld::Notify(MxParam& p_param)
{
	MxLong ret = 0;
	switch (((MxNotificationParam&) p_param).GetNotification()) {
	case c_notificationEndAction: {
		MxPresenter* presenter = (MxPresenter*) ((MxEndActionNotificationParam&) p_param).GetSender();
		Remove(presenter);
		ret = 1;
		break;
	}
	case c_notificationNewPresenter:
		TickleManager()->RegisterClient(this, 100);
		break;
	}
	return ret;
}

// FUNCTION: LEGO1 0x1001f630
LegoCameraController* LegoWorld::VTable0x54()
{
	MxBool success = FALSE;

	if (!VideoManager()) {
		goto done;
	}
	if (!(m_cameraController = new LegoCameraController())) {
		goto done;
	}
	if (m_cameraController->Create() != SUCCESS) {
		goto done;
	}

	m_cameraController->OnViewSize(
		VideoManager()->GetVideoParam().GetRect().GetWidth(),
		VideoManager()->GetVideoParam().GetRect().GetHeight()
	);

	success = TRUE;

done:
	if (!success) {
		if (m_cameraController) {
			delete m_cameraController;
			m_cameraController = NULL;
		}
	}

	return m_cameraController;
}

// STUB: LEGO1 0x1001fc80
void LegoWorld::FUN_1001fc80(IslePathActor* p_actor)
{
}

// STUB: LEGO1 0x10020120
MxS32 LegoWorld::GetCurrPathInfo(LegoPathBoundary** p_path, MxS32& p_value)
{
	// TODO
	return 0;
}

// FUNCTION: LEGO1 0x10020220
void LegoWorld::Add(MxCore* p_object)
{
	if (p_object && !p_object->IsA("LegoWorld") && !p_object->IsA("LegoWorldPresenter")) {
		if (p_object->IsA("LegoAnimPresenter")) {
			LegoAnimPresenter* animPresenter = (LegoAnimPresenter*) p_object;
			if (!strcmpi(animPresenter->GetAction()->GetObjectName(), "ConfigAnimation")) {
				FUN_1003e050(animPresenter);
				animPresenter->GetAction()->SetDuration(animPresenter->GetUnknown0x64()->GetUnknown0x8());
			}
		}

		if (p_object->IsA("MxControlPresenter")) {
			MxPresenterListCursor cursor(&m_controlPresenters);
			MxPresenter* presenter = (MxPresenter*) p_object;

			if (cursor.Find(presenter))
				return;

			m_controlPresenters.Append(presenter);
		}
		else if (p_object->IsA("MxEntity")) {
			LegoEntityListCursor cursor(m_entityList);
			LegoEntity* entity = (LegoEntity*) p_object;

			if (cursor.Find(entity))
				return;

			m_entityList->Append(entity);
		}
		else if (p_object->IsA("LegoLocomotionAnimPresenter") || p_object->IsA("LegoHideAnimPresenter") || p_object->IsA("LegoLoopingAnimPresenter")) {
			MxPresenterListCursor cursor(&m_animPresenters);
			MxPresenter* presenter = (MxPresenter*) p_object;

			if (cursor.Find(presenter))
				return;

			presenter->SendToCompositePresenter(Lego());
			m_animPresenters.Append(presenter);

			if (p_object->IsA("LegoHideAnimPresenter"))
				m_hideAnimPresenter = (LegoHideAnimPresenter*) presenter;
		}
		else if (p_object->IsA("LegoCacheSound")) {
			LegoCacheSoundListCursor cursor(m_cacheSoundList);
			LegoCacheSound* sound = (LegoCacheSound*) p_object;

			if (cursor.Find(sound))
				return;

			m_cacheSoundList->Append(sound);
		}
		else {
			if (m_set0xa8.find((MxPresenter*) p_object) == m_set0xa8.end())
				m_set0xa8.insert((MxPresenter*) p_object);
		}

		if (!m_set0xd0.empty() && p_object->IsA("MxPresenter")) {
			MxPresenter* presenter = (MxPresenter*) p_object;

			if (presenter->IsEnabled()) {
				presenter->Enable(FALSE);
				m_set0xd0.insert(presenter);
			}
		}
	}
}

// STUB: LEGO1 0x10020f10
void LegoWorld::Remove(MxCore* p_object)
{
	// TODO
}

// FUNCTION: LEGO1 0x100213a0
MxCore* LegoWorld::Find(const char* p_class, const char* p_name)
{
	if (!strcmp(p_class, "MxControlPresenter")) {
		MxPresenterListCursor cursor(&m_controlPresenters);
		MxPresenter* presenter;

		while (cursor.Next(presenter)) {
			MxDSAction* action = presenter->GetAction();
			if (!strcmp(action->GetObjectName(), p_name))
				return presenter;
		}

		return NULL;
	}
	else if (!strcmp(p_class, "MxEntity")) {
		LegoEntityListCursor cursor(m_entityList);
		LegoEntity* entity;

		while (cursor.Next(entity)) {
			if (!p_name)
				return entity;

			LegoROI* roi = entity->GetROI();
			if (roi && !strcmpi(roi->GetUnknown0xe4(), p_name))
				return entity;
		}

		return NULL;
	}
	else if (!strcmp(p_class, "LegoAnimPresenter")) {
		MxPresenterListCursor cursor(&m_animPresenters);
		MxPresenter* presenter;

		while (cursor.Next(presenter)) {
			if (!strcmpi(((LegoAnimPresenter*) presenter)->GetActionObjectName(), p_name))
				return presenter;
		}

		return NULL;
	}
	else {
		for (MxPresenterSet::iterator it = m_set0xa8.begin(); it != m_set0xa8.end(); it++) {
			if ((*it)->IsA(p_class) && (*it)->IsA("MxPresenter")) {
				MxPresenter* presenter = (MxPresenter*) *it;
				MxDSAction* action = presenter->GetAction();

				if (!strcmp(action->GetObjectName(), p_name))
					return *it;
			}
		}

		return NULL;
	}
}

// FUNCTION: LEGO1 0x10021790
MxCore* LegoWorld::Find(const MxAtomId& p_atom, MxS32 p_entityId)
{
	LegoEntityListCursor entityCursor(m_entityList);
	LegoEntity* entity;

	while (entityCursor.Next(entity)) {
		if (entity->GetAtom() == p_atom && entity->GetEntityId() == p_entityId)
			return entity;
	}

	MxPresenterListCursor controlPresenterCursor(&m_controlPresenters);
	MxPresenter* presenter;

	while (controlPresenterCursor.Next(presenter)) {
		MxDSAction* action = presenter->GetAction();

		if (action->GetAtomId() == p_atom && action->GetObjectId() == p_entityId)
			return presenter;
	}

	MxPresenterListCursor animPresenterCursor(&m_animPresenters);

	while (animPresenterCursor.Next(presenter)) {
		MxDSAction* action = presenter->GetAction();

		if (action && action->GetAtomId() == p_atom && action->GetObjectId() == p_entityId)
			return presenter;
	}

	for (MxPresenterSet::iterator it = m_set0xa8.begin(); it != m_set0xa8.end(); it++) {
		MxCore* core = *it;

		if (core->IsA("MxPresenter")) {
			MxPresenter* presenter = (MxPresenter*) *it;
			MxDSAction* action = presenter->GetAction();

			if (action->GetAtomId() == p_atom && action->GetObjectId() == p_entityId)
				return *it;
		}
	}

	return NULL;
}

// STUB: LEGO1 0x10021a70
void LegoWorld::VTable0x68(MxBool p_add)
{
	// TODO
}

// FUNCTION: LEGO1 0x10022080
MxResult LegoWorld::Tickle()
{
	if (!m_worldStarted) {
		switch (m_unk0xf4) {
		case 0:
			m_worldStarted = TRUE;
			SetAppCursor(0);
			VTable0x50();
			return TRUE;
		case 2:
			if (FUN_100220e0() == 1)
				break;
		default:
			m_unk0xf4--;
		}
	}
	return TRUE;
}

// STUB: LEGO1 0x100220e0
undefined LegoWorld::FUN_100220e0()
{
	return 0;
}

// FUNCTION: LEGO1 0x10022340
void LegoWorld::VTable0x50()
{
	TickleManager()->UnregisterClient(this);
}

// STUB: LEGO1 0x100727e0
MxBool LegoWorld::FUN_100727e0(MxU32, Mx3DPointFloat& p_loc, Mx3DPointFloat& p_dir, Mx3DPointFloat& p_up)
{
	return FALSE;
}

// STUB: LEGO1 0x10072980
MxBool LegoWorld::FUN_10072980(MxU32, Mx3DPointFloat& p_loc, Mx3DPointFloat& p_dir, Mx3DPointFloat& p_up)
{
	return FALSE;
}

// STUB: LEGO1 0x10073400
void LegoWorld::FUN_10073400()
{
}

// STUB: LEGO1 0x10073430
void LegoWorld::FUN_10073430()
{
}
