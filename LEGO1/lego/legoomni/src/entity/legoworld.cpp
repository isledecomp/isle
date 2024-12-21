#include "legoworld.h"

#include "anim/legoanim.h"
#include "legoanimationmanager.h"
#include "legoanimpresenter.h"
#include "legobuildingmanager.h"
#include "legocachesoundlist.h"
#include "legocachesoundmanager.h"
#include "legocameracontroller.h"
#include "legocontrolmanager.h"
#include "legoentitylist.h"
#include "legogamestate.h"
#include "legoinputmanager.h"
#include "legolocomotionanimpresenter.h"
#include "legonavcontroller.h"
#include "legoplantmanager.h"
#include "legosoundmanager.h"
#include "legoutils.h"
#include "legovideomanager.h"
#include "misc.h"
#include "mxactionnotificationparam.h"
#include "mxcontrolpresenter.h"
#include "mxmisc.h"
#include "mxnotificationmanager.h"
#include "mxnotificationparam.h"
#include "mxticklemanager.h"
#include "mxutilities.h"
#include "viewmanager/viewmanager.h"

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
	m_hideAnim = NULL;
	m_worldStarted = FALSE;

	NotificationManager()->Register(this);
}

// FUNCTION: LEGO1 0x1001d670
// FUNCTION: BETA10 0x10017530
MxBool LegoWorld::VTable0x5c()
{
	// The BETA10 match could also be LegoWorld::Escape(), only the child classes might be able to tell
	return FALSE;
}

// FUNCTION: LEGO1 0x1001d680
MxBool LegoWorld::Escape()
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
			CurrentWorld()->Enable(FALSE);
		}

		SetCurrentWorld(this);
		ControlManager()->FUN_10028df0(&m_controlPresenters);
	}

	SetIsWorldActive(TRUE);
	m_worldId = LegoOmni::e_undefined;
	return SUCCESS;
}

// FUNCTION: LEGO1 0x1001e9d0
// FUNCTION: BETA10 0x100d99ea
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

	if (m_worldId != LegoOmni::e_undefined && m_set0xd0.empty()) {
		PlantManager()->Reset(m_worldId);
		BuildingManager()->Reset();
	}

	if (m_entityList) {
		LegoEntityListCursor cursor(m_entityList);
		LegoEntity* entity;

		while (cursor.First(entity)) {
			cursor.Detach();

			if (!(entity->GetFlags() & LegoEntity::c_managerOwned)) {
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
			SoundManager()->GetCacheSoundManager()->Destroy(sound);
		}

		delete m_cacheSoundList;
		m_cacheSoundList = NULL;
	}

	while (!m_roiList.empty()) {
		LegoROI* roi = m_roiList.front();
		m_roiList.pop_front();
		delete roi;
	}

	if (!p_fromDestructor) {
		LegoEntity::Destroy(FALSE);
	}
}

// FUNCTION: LEGO1 0x1001f5e0
// FUNCTION: BETA10 0x100d9f5f
MxLong LegoWorld::Notify(MxParam& p_param)
{
	MxLong result = 0;

	switch (((MxNotificationParam&) p_param).GetNotification()) {
	case c_notificationEndAction: {
		MxPresenter* presenter = (MxPresenter*) ((MxEndActionNotificationParam&) p_param).GetSender();
		Remove(presenter);
		result = 1;
		break;
	}
	case c_notificationNewPresenter:
		TickleManager()->RegisterClient(this, 100);
		break;
	}

	return result;
}

// FUNCTION: LEGO1 0x1001f630
// FUNCTION: BETA10 0x100d9fc2
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

// FUNCTION: LEGO1 0x1001f720
// FUNCTION: BETA10 0x100da24b
MxResult LegoWorld::PlaceActor(
	LegoPathActor* p_actor,
	const char* p_name,
	MxS32 p_src,
	float p_srcScale,
	MxS32 p_dest,
	float p_destScale
)
{
	LegoPathControllerListCursor cursor(&m_list0x68);
	LegoPathController* controller;

	while (cursor.Next(controller)) {
		if (controller->PlaceActor(p_actor, p_name, p_src, p_srcScale, p_dest, p_destScale) == SUCCESS) {
			return SUCCESS;
		}
	}

	return FAILURE;
}

// FUNCTION: LEGO1 0x1001fa70
MxResult LegoWorld::PlaceActor(LegoPathActor* p_actor)
{
	LegoPathControllerListCursor cursor(&m_list0x68);
	LegoPathController* controller;

	while (cursor.Next(controller)) {
		if (controller->PlaceActor(p_actor) == SUCCESS) {
			return SUCCESS;
		}
	}

	return FAILURE;
}

// FUNCTION: LEGO1 0x1001fb70
MxResult LegoWorld::PlaceActor(
	LegoPathActor* p_actor,
	LegoAnimPresenter* p_presenter,
	Vector3& p_position,
	Vector3& p_direction
)
{
	LegoPathControllerListCursor cursor(&m_list0x68);
	LegoPathController* controller;

	while (cursor.Next(controller)) {
		if (controller->PlaceActor(p_actor, p_presenter, p_position, p_direction) == SUCCESS) {
			return SUCCESS;
		}
	}

	return FAILURE;
}

// FUNCTION: LEGO1 0x1001fc80
// FUNCTION: BETA10 0x100da4bf
void LegoWorld::RemoveActor(LegoPathActor* p_actor)
{
	LegoPathControllerListCursor cursor(&m_list0x68);
	LegoPathController* controller;

	while (cursor.Next(controller)) {
		if (controller->RemoveActor(p_actor) == SUCCESS) {
			break;
		}
	}
}

// FUNCTION: LEGO1 0x1001fda0
// FUNCTION: BETA10 0x100da621
void LegoWorld::FUN_1001fda0(LegoAnimPresenter* p_presenter)
{
	LegoPathControllerListCursor cursor(&m_list0x68);
	LegoPathController* controller;

	while (cursor.Next(controller)) {
		controller->FUN_100468f0(p_presenter);
	}
}

// FUNCTION: LEGO1 0x1001fe90
// FUNCTION: BETA10 0x100da6b5
void LegoWorld::FUN_1001fe90(LegoAnimPresenter* p_presenter)
{
	LegoPathControllerListCursor cursor(&m_list0x68);
	LegoPathController* controller;

	while (cursor.Next(controller)) {
		controller->FUN_10046930(p_presenter);
	}
}

// FUNCTION: LEGO1 0x1001ff80
void LegoWorld::AddPath(LegoPathController* p_controller)
{
	p_controller->FUN_10046bb0(this);
	m_list0x68.Append(p_controller);
}

// FUNCTION: LEGO1 0x10020020
// FUNCTION: BETA10 0x100da77c
LegoPathBoundary* LegoWorld::FindPathBoundary(const char* p_name)
{
	LegoPathControllerListCursor cursor(&m_list0x68);
	LegoPathController* controller;

	while (cursor.Next(controller)) {
		LegoPathBoundary* boundary = controller->GetPathBoundary(p_name);

		if (boundary) {
			return boundary;
		}
	}

	return NULL;
}

// FUNCTION: LEGO1 0x10020120
MxResult LegoWorld::GetCurrPathInfo(LegoPathBoundary** p_boundaries, MxS32& p_numL)
{
	LegoPathControllerListCursor cursor(&m_list0x68);
	LegoPathController* controller;

	cursor.Next(controller);

	if (!controller) {
		return FAILURE;
	}

	return controller->FUN_10046b30(*p_boundaries, p_numL);
}

// FUNCTION: LEGO1 0x10020220
// FUNCTION: BETA10 0x100da90b
void LegoWorld::Add(MxCore* p_object)
{
	if (p_object && !p_object->IsA("LegoWorld") && !p_object->IsA("LegoWorldPresenter")) {
		if (p_object->IsA("LegoAnimPresenter")) {
			LegoAnimPresenter* animPresenter = (LegoAnimPresenter*) p_object;

			if (!strcmpi(animPresenter->GetAction()->GetObjectName(), "ConfigAnimation")) {
				FUN_1003e050(animPresenter);
				animPresenter->GetAction()->SetDuration(animPresenter->GetAnimation()->GetDuration());
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
				m_hideAnim = (LegoHideAnimPresenter*) p_object;
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
// FUNCTION: BETA10 0x100dad2a
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
				m_hideAnim = NULL;
			}
		}
		else if (p_object->IsA("MxEntity")) {
			if (p_object->IsA("LegoPathActor")) {
				RemoveActor((LegoPathActor*) p_object);
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
// FUNCTION: BETA10 0x100db027
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
			if (roi && !strcmpi(roi->GetName(), p_name)) {
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
		if (entity->GetAtomId() == p_atom && entity->GetEntityId() == p_entityId) {
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
// FUNCTION: BETA10 0x100db758
void LegoWorld::Enable(MxBool p_enable)
{
	if (p_enable && !m_set0xd0.empty()) {
		if (CurrentWorld() != this) {
			if (CurrentWorld()) {
				AnimationManager()->FUN_10061010(FALSE);
				CurrentWorld()->Enable(FALSE);

				LegoEntityListCursor cursor(m_entityList);
				LegoEntity* entity;

				while (cursor.Next(entity)) {
					if (entity->GetROI()) {
						entity->GetROI()->SetEntity(entity);
						GetViewManager()->Add(entity->GetROI());
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

			if (m_worldId != LegoOmni::e_undefined) {
				PlantManager()->LoadWorldInfo(m_worldId);
				AnimationManager()->LoadWorldInfo(m_worldId);
				BuildingManager()->LoadWorldInfo();
				AnimationManager()->Resume();
			}

			GameState()->ResetROI();
			SetIsWorldActive(TRUE);
		}
	}
	else if (!p_enable && m_set0xd0.empty()) {
		MxPresenter* presenter;
		LegoPathController* controller;
		LegoPathActor* actor = UserActor();

		if (actor) {
			RemoveActor(actor);
		}

		AnimationManager()->Reset(FALSE);
		m_set0xd0.insert(this);

		if (m_worldId != LegoOmni::e_undefined) {
			PlantManager()->Reset(m_worldId);
			BuildingManager()->Reset();
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
			SetAppCursor(e_cursorArrow);
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
