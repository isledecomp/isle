#include "legoworld.h"

#include "legoanimationmanager.h"
#include "legoanimpresenter.h"
#include "legobuildingmanager.h"
#include "legocontrolmanager.h"
#include "legogamestate.h"
#include "legoinputmanager.h"
#include "legolocomotionanimpresenter.h"
#include "legonavcontroller.h"
#include "legoomni.h"
#include "legoplantmanager.h"
#include "legosoundmanager.h"
#include "legoutil.h"
#include "legovideomanager.h"
#include "mxactionnotificationparam.h"
#include "mxcontrolpresenter.h"
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
	m_startupTicks = e_four;
	m_cameraController = NULL;
	m_entityList = NULL;
	m_cacheSoundList = NULL;
	m_destroyed = FALSE;
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

// FUNCTION: LEGO1 0x1001dfa0
LegoWorld::~LegoWorld()
{
	Destroy(TRUE);

	TickleManager()->UnregisterClient(this);
	NotificationManager()->Unregister(this);
}

// FUNCTION: LEGO1 0x1001e0b0
MxResult LegoWorld::Create(MxDSAction& p_dsAction)
{
	MxEntity::Create(p_dsAction);

	m_entityList = new LegoEntityList(TRUE);

	if (!m_entityList) {
		return FAILURE;
	}

	m_cacheSoundList = new LegoCacheSoundList(TRUE);

	if (!m_cacheSoundList) {
		return FAILURE;
	}

	if (!VTable0x54()) {
		return FAILURE;
	}

	if (p_dsAction.GetFlags() & MxDSAction::c_enabled) {
		if (CurrentWorld()) {
			CurrentWorld()->Enable(0);
		}

		SetCurrentWorld(this);
		ControlManager()->FUN_10028df0(&m_controlPresenters);
	}

	SetIsWorldActive(TRUE);
	m_unk0xec = -1;

	return SUCCESS;
}

// FUNCTION: LEGO1 0x1001e9d0
void LegoWorld::Destroy(MxBool p_fromDestructor)
{
	m_destroyed = TRUE;

	if (CurrentWorld() == this) {
		ControlManager()->FUN_10028df0(NULL);
		SetCurrentWorld(NULL);
	}

	m_list0x68.DeleteAll();

	if (m_cameraController) {
		delete m_cameraController;
		m_cameraController = NULL;
	}

	MxPresenterListCursor animPresenterCursor(&m_animPresenters);
	MxPresenter* presenter;

	while (animPresenterCursor.First(presenter)) {
		animPresenterCursor.Detach();

		MxDSAction* action = presenter->GetAction();
		if (action) {
			if (presenter->IsA("LegoLocomotionAnimPresenter")) {
				LegoLocomotionAnimPresenter* animPresenter = (LegoLocomotionAnimPresenter*) presenter;

				animPresenter->DecrementUnknown0xd4();
				if (animPresenter->GetUnknown0xd4() == 0) {
					FUN_100b7220(action, MxDSAction::c_world, FALSE);
					presenter->EndAction();
				}
			}
			else {
				FUN_100b7220(action, MxDSAction::c_world, FALSE);
				presenter->EndAction();
			}
		}
	}

	while (!m_set0xa8.empty()) {
		MxCoreSet::iterator it = m_set0xa8.begin();
		MxCore* object = *it;
		m_set0xa8.erase(it);

		if (object->IsA("MxPresenter")) {
			MxPresenter* presenter = (MxPresenter*) object;
			MxDSAction* action = presenter->GetAction();

			if (action) {
				FUN_100b7220(action, MxDSAction::c_world, FALSE);
				presenter->EndAction();
			}
		}
		else {
			delete object;
		}
	}

	MxPresenterListCursor controlPresenterCursor(&m_controlPresenters);

	while (controlPresenterCursor.First(presenter)) {
		controlPresenterCursor.Detach();

		MxDSAction* action = presenter->GetAction();
		if (action) {
			FUN_100b7220(action, MxDSAction::c_world, FALSE);
			presenter->EndAction();
		}
	}

	if (m_unk0xec != -1 && m_set0xd0.empty()) {
		PlantManager()->FUN_100263a0(m_unk0xec);
		BuildingManager()->FUN_1002fb30();
	}

	if (m_entityList) {
		LegoEntityListCursor cursor(m_entityList);
		LegoEntity* entity;

		while (cursor.First(entity)) {
			cursor.Detach();

			if (!(entity->GetFlags() & LegoEntity::c_bit2)) {
				delete entity;
			}
		}

		delete m_entityList;
		m_entityList = NULL;
	}

	if (m_cacheSoundList) {
		LegoCacheSoundListCursor cursor(m_cacheSoundList);
		LegoCacheSound* sound;

		while (cursor.First(sound)) {
			cursor.Detach();
			SoundManager()->GetUnknown0x40()->FUN_1003dc40(&sound);
		}

		delete m_cacheSoundList;
		m_cacheSoundList = NULL;
	}

	while (!m_list0xe0.empty()) {
		AutoROI* roi = m_list0xe0.front();
		m_list0xe0.pop_front();
		delete roi;
	}

	if (!p_fromDestructor) {
		LegoEntity::Destroy(FALSE);
	}
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

// FUNCTION: LEGO1 0x1001fc80
void LegoWorld::FUN_1001fc80(IslePathActor* p_actor)
{
	LegoPathControllerListCursor cursor(&m_list0x68);
	LegoPathController* controller;

	while (cursor.Next(controller)) {
		if (!controller->FUN_10046770(p_actor)) {
			break;
		}
	}
}

// FUNCTION: LEGO1 0x10020120
MxResult LegoWorld::GetCurrPathInfo(LegoPathBoundary** p_path, MxS32& p_value)
{
	LegoPathControllerListCursor cursor(&m_list0x68);
	LegoPathController* controller;

	cursor.Next(controller);

	if (!controller) {
		return FAILURE;
	}

	return controller->FUN_10046b30(p_path, p_value);
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

			if (cursor.Find((MxPresenter*) p_object)) {
				return;
			}

			m_controlPresenters.Append((MxPresenter*) p_object);
		}
		else if (p_object->IsA("MxEntity")) {
			LegoEntityListCursor cursor(m_entityList);

			if (cursor.Find((LegoEntity*) p_object)) {
				return;
			}

			m_entityList->Append((LegoEntity*) p_object);
		}
		else if (p_object->IsA("LegoLocomotionAnimPresenter") || p_object->IsA("LegoHideAnimPresenter") || p_object->IsA("LegoLoopingAnimPresenter")) {
			MxPresenterListCursor cursor(&m_animPresenters);

			if (cursor.Find((MxPresenter*) p_object)) {
				return;
			}

			((MxPresenter*) p_object)->SendToCompositePresenter(Lego());
			m_animPresenters.Append(((MxPresenter*) p_object));

			if (p_object->IsA("LegoHideAnimPresenter")) {
				m_hideAnimPresenter = (LegoHideAnimPresenter*) p_object;
			}
		}
		else if (p_object->IsA("LegoCacheSound")) {
			LegoCacheSoundListCursor cursor(m_cacheSoundList);

			if (cursor.Find((LegoCacheSound*) p_object)) {
				return;
			}

			m_cacheSoundList->Append((LegoCacheSound*) p_object);
		}
		else {
			if (m_set0xa8.find(p_object) == m_set0xa8.end()) {
				m_set0xa8.insert(p_object);
			}
		}

		if (!m_set0xd0.empty() && p_object->IsA("MxPresenter")) {
			if (((MxPresenter*) p_object)->IsEnabled()) {
				((MxPresenter*) p_object)->Enable(FALSE);
				m_set0xd0.insert(p_object);
			}
		}
	}
}

// FUNCTION: LEGO1 0x10020f10
void LegoWorld::Remove(MxCore* p_object)
{
	if (p_object) {
		MxCoreSet::iterator it;

		if (p_object->IsA("MxControlPresenter")) {
			MxPresenterListCursor cursor(&m_controlPresenters);

			if (cursor.Find((MxControlPresenter*) p_object)) {
				cursor.Detach();
				((MxControlPresenter*) p_object)->GetAction()->SetOrigin(Lego());
				((MxControlPresenter*) p_object)->VTable0x68(TRUE);
			}
		}
		else if (p_object->IsA("LegoLocomotionAnimPresenter") || p_object->IsA("LegoHideAnimPresenter") || p_object->IsA("LegoLoopingAnimPresenter")) {
			MxPresenterListCursor cursor(&m_animPresenters);

			if (cursor.Find((MxPresenter*) p_object)) {
				cursor.Detach();
			}

			if (p_object->IsA("LegoHideAnimPresenter")) {
				m_hideAnimPresenter = NULL;
			}
		}
		else if (p_object->IsA("MxEntity")) {
			if (p_object->IsA("LegoPathActor")) {
				FUN_1001fc80((IslePathActor*) p_object);
			}

			if (m_entityList) {
				LegoEntityListCursor cursor(m_entityList);

				if (cursor.Find((LegoEntity*) p_object)) {
					cursor.Detach();
				}
			}
		}
		else if (p_object->IsA("LegoCacheSound")) {
			LegoCacheSoundListCursor cursor(m_cacheSoundList);

			if (cursor.Find((LegoCacheSound*) p_object)) {
				cursor.Detach();
			}
		}
		else {
			it = m_set0xa8.find(p_object);
			if (it != m_set0xa8.end()) {
				m_set0xa8.erase(it);
			}
		}

		it = m_set0xd0.find(p_object);
		if (it != m_set0xd0.end()) {
			m_set0xd0.erase(it);
		}
	}
}

// FUNCTION: LEGO1 0x100213a0
MxCore* LegoWorld::Find(const char* p_class, const char* p_name)
{
	if (!strcmp(p_class, "MxControlPresenter")) {
		MxPresenterListCursor cursor(&m_controlPresenters);
		MxPresenter* presenter;

		while (cursor.Next(presenter)) {
			MxDSAction* action = presenter->GetAction();
			if (!strcmp(action->GetObjectName(), p_name)) {
				return presenter;
			}
		}

		return NULL;
	}
	else if (!strcmp(p_class, "MxEntity")) {
		LegoEntityListCursor cursor(m_entityList);
		LegoEntity* entity;

		while (cursor.Next(entity)) {
			if (!p_name) {
				return entity;
			}

			LegoROI* roi = entity->GetROI();
			if (roi && !strcmpi(roi->GetUnknown0xe4(), p_name)) {
				return entity;
			}
		}

		return NULL;
	}
	else if (!strcmp(p_class, "LegoAnimPresenter")) {
		MxPresenterListCursor cursor(&m_animPresenters);
		MxPresenter* presenter;

		while (cursor.Next(presenter)) {
			if (!strcmpi(((LegoAnimPresenter*) presenter)->GetActionObjectName(), p_name)) {
				return presenter;
			}
		}

		return NULL;
	}
	else {
		for (MxCoreSet::iterator it = m_set0xa8.begin(); it != m_set0xa8.end(); it++) {
			if ((*it)->IsA(p_class) && (*it)->IsA("MxPresenter")) {
				MxPresenter* presenter = (MxPresenter*) *it;
				MxDSAction* action = presenter->GetAction();

				if (!strcmp(action->GetObjectName(), p_name)) {
					return *it;
				}
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
		if (entity->GetAtom() == p_atom && entity->GetEntityId() == p_entityId) {
			return entity;
		}
	}

	MxPresenterListCursor controlPresenterCursor(&m_controlPresenters);
	MxPresenter* presenter;

	while (controlPresenterCursor.Next(presenter)) {
		MxDSAction* action = presenter->GetAction();

		if (action->GetAtomId() == p_atom && action->GetObjectId() == p_entityId) {
			return presenter;
		}
	}

	MxPresenterListCursor animPresenterCursor(&m_animPresenters);

	while (animPresenterCursor.Next(presenter)) {
		MxDSAction* action = presenter->GetAction();

		if (action && action->GetAtomId() == p_atom && action->GetObjectId() == p_entityId) {
			return presenter;
		}
	}

	for (MxCoreSet::iterator it = m_set0xa8.begin(); it != m_set0xa8.end(); it++) {
		MxCore* core = *it;

		if (core->IsA("MxPresenter")) {
			MxPresenter* presenter = (MxPresenter*) *it;
			MxDSAction* action = presenter->GetAction();

			if (action->GetAtomId() == p_atom && action->GetObjectId() == p_entityId) {
				return *it;
			}
		}
	}

	return NULL;
}

// FUNCTION: LEGO1 0x10021a70
void LegoWorld::Enable(MxBool p_enable)
{
	if (p_enable && !m_set0xd0.empty()) {
		if (CurrentWorld() != this) {
			if (CurrentWorld()) {
				AnimationManager()->FUN_10061010(0);
				CurrentWorld()->Enable(FALSE);

				LegoEntityListCursor cursor(m_entityList);
				LegoEntity* entity;

				while (cursor.Next(entity)) {
					if (entity->GetROI()) {
						entity->GetROI()->SetUnknown0x104(entity);
						GetViewManager()->AddToUnknown0x08(entity->GetROI());
					}
				}
			}

			while (!m_set0xd0.empty()) {
				MxCoreSet::iterator it = m_set0xd0.begin();

				if ((*it)->IsA("MxPresenter")) {
					((MxPresenter*) *it)->Enable(TRUE);
				}
				else if ((*it)->IsA("LegoPathController")) {
					((LegoPathController*) *it)->Enable(TRUE);
				}

				m_set0xd0.erase(it);
			}

			SetCurrentWorld(this);
			ControlManager()->FUN_10028df0(&m_controlPresenters);
			InputManager()->SetCamera(m_cameraController);

			if (m_cameraController) {
				InputManager()->Register(m_cameraController->GetNavController());
				Lego()->SetNavController(m_cameraController->GetNavController());
			}

			if (m_unk0xec != -1) {
				PlantManager()->FUN_10026360(m_unk0xec);
				AnimationManager()->FUN_1005f720(m_unk0xec);
				BuildingManager()->FUN_1002fa00();
				AnimationManager()->FUN_1005f0b0();
			}

			GameState()->FUN_10039940();
			SetIsWorldActive(TRUE);
		}
	}
	else if (!p_enable && m_set0xd0.empty()) {
		MxPresenter* presenter;
		LegoPathController* controller;
		IslePathActor* vehicle = CurrentVehicle();

		if (vehicle) {
			FUN_1001fc80(vehicle);
		}

		AnimationManager()->FUN_1005ee80(FALSE);
		m_set0xd0.insert(this);

		if (m_unk0xec != -1) {
			PlantManager()->FUN_100263a0(m_unk0xec);
			BuildingManager()->FUN_1002fb30();
		}

		MxPresenterListCursor controlPresenterCursor(&m_controlPresenters);

		while (controlPresenterCursor.Next(presenter)) {
			if (presenter->IsEnabled()) {
				m_set0xd0.insert(presenter);
				presenter->Enable(FALSE);
			}
		}

		for (MxCoreSet::iterator it = m_set0xa8.begin(); it != m_set0xa8.end(); it++) {
			if ((*it)->IsA("LegoActionControlPresenter") ||
				((*it)->IsA("MxPresenter") && ((MxPresenter*) *it)->IsEnabled())) {
				m_set0xd0.insert(*it);
				((MxPresenter*) *it)->Enable(FALSE);
			}
		}

		if (CurrentWorld() && CurrentWorld() == this) {
			ControlManager()->FUN_10028df0(NULL);
			Lego()->SetCurrentWorld(NULL);
		}

		if (InputManager()->GetCamera() == m_cameraController) {
			InputManager()->ClearCamera();
		}

		if (m_cameraController) {
			InputManager()->UnRegister(m_cameraController->GetNavController());

			if (NavController() == m_cameraController->GetNavController()) {
				Lego()->SetNavController(NULL);
			}
		}

		LegoPathControllerListCursor pathControllerCursor(&m_list0x68);

		while (pathControllerCursor.Next(controller)) {
			controller->Enable(FALSE);
			m_set0xd0.insert(controller);
		}

		GetViewManager()->RemoveAll(NULL);
	}
}

// FUNCTION: LEGO1 0x10022080
MxResult LegoWorld::Tickle()
{
	if (!m_worldStarted) {
		switch (m_startupTicks) {
		case e_start:
			m_worldStarted = TRUE;
			SetAppCursor(0);
			ReadyWorld();
			return TRUE;
		case e_two:
			if (PresentersPending()) {
				break;
			}
		default:
			m_startupTicks--;
		}
	}

	return TRUE;
}

// FUNCTION: LEGO1 0x100220e0
MxBool LegoWorld::PresentersPending()
{
	MxPresenterListCursor controlPresenterCursor(&m_controlPresenters);
	MxPresenter* presenter;

	while (controlPresenterCursor.Next(presenter)) {
		if (presenter->IsEnabled() && !presenter->HasTickleStatePassed(MxPresenter::e_starting)) {
			return TRUE;
		}
	}

	MxPresenterListCursor animPresenterCursor(&m_animPresenters);

	while (animPresenterCursor.Next(presenter)) {
		if (presenter->IsEnabled()) {
			if (presenter->IsA("LegoLocomotionAnimPresenter")) {
				if (!presenter->HasTickleStatePassed(MxPresenter::e_ready)) {
					return TRUE;
				}
			}
			else {
				if (!presenter->HasTickleStatePassed(MxPresenter::e_starting)) {
					return TRUE;
				}
			}
		}
	}

	for (MxCoreSet::iterator it = m_set0xa8.begin(); it != m_set0xa8.end(); it++) {
		if ((*it)->IsA("MxPresenter")) {
			presenter = (MxPresenter*) *it;

			if (presenter->IsEnabled() && !presenter->HasTickleStatePassed(MxPresenter::e_starting)) {
				return TRUE;
			}
		}
	}

	return FALSE;
}

// FUNCTION: LEGO1 0x10022340
void LegoWorld::ReadyWorld()
{
	TickleManager()->UnregisterClient(this);
}
