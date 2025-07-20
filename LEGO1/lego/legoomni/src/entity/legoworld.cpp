#include "legoworld.h"

#include "anim/legoanim.h"
#include "legoanimationmanager.h"
#include "legoanimpresenter.h"
#include "legobuildingmanager.h"
#include "legocachesoundmanager.h"
#include "legocameracontroller.h"
#include "legocontrolmanager.h"
#include "legogamestate.h"
#include "legoinputmanager.h"
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
LegoWorld::LegoWorld() : m_pathControllerList(TRUE)
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

	if (!InitializeCameraController()) {
		return FAILURE;
	}

	if (p_dsAction.GetFlags() & MxDSAction::c_enabled) {
		if (CurrentWorld()) {
			CurrentWorld()->Enable(FALSE);
		}

		SetCurrentWorld(this);
		ControlManager()->SetPresenterList(&m_controlPresenters);
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
		ControlManager()->SetPresenterList(NULL);
		SetCurrentWorld(NULL);
	}

	m_pathControllerList.DeleteAll();

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

				animPresenter->DecrementWorldRefCounter();
				if (animPresenter->GetWorldRefCounter() == 0) {
					ApplyMask(action, MxDSAction::c_world, FALSE);
					presenter->EndAction();
				}
			}
			else {
				ApplyMask(action, MxDSAction::c_world, FALSE);
				presenter->EndAction();
			}
		}
	}

	while (!m_objects.empty()) {
		MxCoreSet::iterator it = m_objects.begin();
		MxCore* object = *it;
		m_objects.erase(it);

		if (object->IsA("MxPresenter")) {
			MxPresenter* presenter = (MxPresenter*) object;
			MxDSAction* action = presenter->GetAction();

			if (action) {
				ApplyMask(action, MxDSAction::c_world, FALSE);
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
			ApplyMask(action, MxDSAction::c_world, FALSE);
			presenter->EndAction();
		}
	}

	if (m_worldId != LegoOmni::e_undefined && m_disabledObjects.empty()) {
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
LegoCameraController* LegoWorld::InitializeCameraController()
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
	LegoPathControllerListCursor cursor(&m_pathControllerList);
	LegoPathController* controller;

	while (cursor.Next(controller)) {
		if (controller->PlaceActor(p_actor, p_name, p_src, p_srcScale, p_dest, p_destScale) == SUCCESS) {
			return SUCCESS;
		}
	}

	return FAILURE;
}

// FUNCTION: LEGO1 0x1001fa70
// FUNCTION: BETA10 0x100da328
MxResult LegoWorld::PlaceActor(LegoPathActor* p_actor)
{
	LegoPathControllerListCursor cursor(&m_pathControllerList);
	LegoPathController* controller;

	while (cursor.Next(controller)) {
		if (controller->PlaceActor(p_actor) == SUCCESS) {
			return SUCCESS;
		}
	}

	return FAILURE;
}

// FUNCTION: LEGO1 0x1001fb70
// FUNCTION: BETA10 0x100da3f1
MxResult LegoWorld::PlaceActor(
	LegoPathActor* p_actor,
	LegoAnimPresenter* p_presenter,
	Vector3& p_position,
	Vector3& p_direction
)
{
	LegoPathControllerListCursor cursor(&m_pathControllerList);
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
	LegoPathControllerListCursor cursor(&m_pathControllerList);
	LegoPathController* controller;

	while (cursor.Next(controller)) {
		if (controller->RemoveActor(p_actor) == SUCCESS) {
			break;
		}
	}
}

// FUNCTION: BETA10 0x100da560
MxBool LegoWorld::ActorExists(LegoPathActor* p_actor)
{
	LegoPathControllerListCursor cursor(&m_pathControllerList);
	LegoPathController* controller;

	while (cursor.Next(controller)) {
		if (controller->ActorExists(p_actor) == TRUE) {
			return TRUE;
		}
	}

	return FALSE;
}

// FUNCTION: LEGO1 0x1001fda0
// FUNCTION: BETA10 0x100da621
void LegoWorld::AddPresenterIfInRange(LegoAnimPresenter* p_presenter)
{
	LegoPathControllerListCursor cursor(&m_pathControllerList);
	LegoPathController* controller;

	while (cursor.Next(controller)) {
		controller->AddPresenterIfInRange(p_presenter);
	}
}

// FUNCTION: LEGO1 0x1001fe90
// FUNCTION: BETA10 0x100da6b5
void LegoWorld::RemovePresenterFromBoundaries(LegoAnimPresenter* p_presenter)
{
	LegoPathControllerListCursor cursor(&m_pathControllerList);
	LegoPathController* controller;

	while (cursor.Next(controller)) {
		controller->RemovePresenterFromBoundaries(p_presenter);
	}
}

// FUNCTION: LEGO1 0x1001ff80
void LegoWorld::AddPath(LegoPathController* p_controller)
{
	p_controller->SetWorld(this);
	m_pathControllerList.Append(p_controller);
}

// FUNCTION: LEGO1 0x10020020
// FUNCTION: BETA10 0x100da77c
LegoPathBoundary* LegoWorld::FindPathBoundary(const char* p_name)
{
	LegoPathControllerListCursor cursor(&m_pathControllerList);
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
	LegoPathControllerListCursor cursor(&m_pathControllerList);
	LegoPathController* controller;

	cursor.Next(controller);

	if (!controller) {
		return FAILURE;
	}

	return controller->GetBoundaries(*p_boundaries, p_numL);
}

// FUNCTION: LEGO1 0x10020220
// FUNCTION: BETA10 0x100da90b
void LegoWorld::Add(MxCore* p_object)
{
	if (p_object == NULL || p_object->IsA("LegoWorld") || p_object->IsA("LegoWorldPresenter")) {
		return;
	}

#ifndef BETA10
	if (p_object->IsA("LegoAnimPresenter")) {
		if (!strcmpi(((LegoAnimPresenter*) p_object)->GetAction()->GetObjectName(), "ConfigAnimation")) {
			CalculateViewFromAnimation((LegoAnimPresenter*) p_object);
			((LegoAnimPresenter*) p_object)
				->GetAction()
				->SetDuration(((LegoAnimPresenter*) p_object)->GetAnimation()->GetDuration());
		}
	}
#endif

	if (p_object->IsA("MxControlPresenter")) {
		MxPresenterListCursor cursor(&m_controlPresenters);

		if (cursor.Find((MxPresenter*) p_object)) {
			assert(0);
			return;
		}

		m_controlPresenters.Append((MxPresenter*) p_object);
	}
	else if (p_object->IsA("MxEntity")) {
		LegoEntityListCursor cursor(m_entityList);

		if (cursor.Find((LegoEntity*) p_object)) {
			assert(0);
			return;
		}

		m_entityList->Append((LegoEntity*) p_object);
	}
	else if (p_object->IsA("LegoLocomotionAnimPresenter") || p_object->IsA("LegoHideAnimPresenter") || p_object->IsA("LegoLoopingAnimPresenter")) {
		MxPresenterListCursor cursor(&m_animPresenters);

		if (cursor.Find((MxPresenter*) p_object)) {
			assert(0);
			return;
		}

		((MxPresenter*) p_object)->SendToCompositePresenter(Lego());
		m_animPresenters.Append(((MxPresenter*) p_object));

		if (p_object->IsA("LegoHideAnimPresenter")) {
			m_hideAnim = (LegoHideAnimPresenter*) p_object;
		}
	}
#ifndef BETA10
	else if (p_object->IsA("LegoCacheSound")) {
		LegoCacheSoundListCursor cursor(m_cacheSoundList);

		if (cursor.Find((LegoCacheSound*) p_object)) {
			assert(0); // ?
			return;
		}

		m_cacheSoundList->Append((LegoCacheSound*) p_object);
	}
#endif
	else {
		MxCoreSet::iterator it = m_objects.find(p_object);
		if (it == m_objects.end()) {
#ifdef BETA10
			if (p_object->IsA("MxPresenter")) {
				assert(static_cast<MxPresenter*>(p_object)->GetAction());
			}
#endif

			m_objects.insert(p_object);
		}
		else {
			assert(0);
		}
	}

	if (m_disabledObjects.size() != 0 && p_object->IsA("MxPresenter")) {
		if (((MxPresenter*) p_object)->IsEnabled()) {
			((MxPresenter*) p_object)->Enable(FALSE);
			m_disabledObjects.insert(p_object);
		}
	}
}

// FUNCTION: LEGO1 0x10020f10
// FUNCTION: BETA10 0x100dad2a
void LegoWorld::Remove(MxCore* p_object)
{
	MxCoreSet::iterator it;

	if (p_object == NULL) {
		return;
	}

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
#ifndef BETA10
	else if (p_object->IsA("LegoCacheSound")) {
		LegoCacheSoundListCursor cursor(m_cacheSoundList);

		if (cursor.Find((LegoCacheSound*) p_object)) {
			cursor.Detach();
		}
	}
#endif
	else {
		it = m_objects.find(p_object);
		if (it != m_objects.end()) {
			m_objects.erase(it);
		}
	}

	it = m_disabledObjects.find(p_object);
	if (it != m_disabledObjects.end()) {
		m_disabledObjects.erase(it);
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
			if (!strcmp(presenter->GetAction()->GetObjectName(), p_name)) {
				return presenter;
			}
		}

		return NULL;
	}

	if (!strcmp(p_class, "MxEntity")) {
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

	if (!strcmp(p_class, "LegoAnimPresenter")) {
		MxPresenterListCursor cursor(&m_animPresenters);
		MxPresenter* presenter;

		while (cursor.Next(presenter)) {
			if (!strcmpi(((LegoAnimPresenter*) presenter)->GetActionObjectName(), p_name)) {
				return presenter;
			}
		}

		return NULL;
	}

	for (MxCoreSet::iterator i = m_objects.begin(); i != m_objects.end(); i++) {
		if ((*i)->IsA(p_class) && (*i)->IsA("MxPresenter")) {
			assert(((MxPresenter*) (*i))->GetAction());

			if (!strcmp(((MxPresenter*) (*i))->GetAction()->GetObjectName(), p_name)) {
				return *i;
			}
		}
	}

	return NULL;
}

// FUNCTION: LEGO1 0x10021790
// FUNCTION: BETA10 0x100db3de
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

	for (MxCoreSet::iterator it = m_objects.begin(); it != m_objects.end(); it++) {
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
	MxCoreSet::iterator it;

	if (p_enable && m_disabledObjects.size() != 0) {
		if (CurrentWorld() == this) {
			return;
		}
		if (CurrentWorld()) {
			AnimationManager()->FUN_10061010(FALSE);
			CurrentWorld()->Enable(FALSE);

			LegoEntityListCursor cursor(m_entityList);
			LegoEntity* entity;

			while (cursor.Next(entity)) {
				assert(entity->GetROI());

				if (entity->GetROI()) {
#ifndef BETA10
					entity->GetROI()->SetEntity(entity);
#endif
					GetViewManager()->Add(entity->GetROI());
				}
			}
		}

		while (m_disabledObjects.size() != 0) {
			it = m_disabledObjects.begin();

			if ((*it)->IsA("MxPresenter")) {
				((MxPresenter*) *it)->Enable(TRUE);
			}
			else if ((*it)->IsA("LegoPathController")) {
				((LegoPathController*) *it)->Enable(TRUE);
			}

			m_disabledObjects.erase(it);
		}

		SetCurrentWorld(this);
		ControlManager()->SetPresenterList(&m_controlPresenters);
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
#ifndef BETA10
		SetIsWorldActive(TRUE);
#endif
	}
	else if (!p_enable && m_disabledObjects.size() == 0) {
		MxPresenter* presenter;
		LegoPathController* controller;
		LegoPathActor* actor = UserActor();

		if (actor) {
			RemoveActor(actor);
		}

		AnimationManager()->Reset(FALSE);
		m_disabledObjects.insert(this);

		if (m_worldId != LegoOmni::e_undefined) {
			PlantManager()->Reset(m_worldId);
#ifndef BETA10
			BuildingManager()->Reset();
#endif
		}

		MxPresenterListCursor controlPresenterCursor(&m_controlPresenters);

		while (controlPresenterCursor.Next(presenter)) {
			if (presenter->IsEnabled()) {
				m_disabledObjects.insert(presenter);
				presenter->Enable(FALSE);
			}
		}

		for (MxCoreSet::iterator it = m_objects.begin(); it != m_objects.end(); it++) {
			if ((*it)->IsA("LegoActionControlPresenter") ||
				((*it)->IsA("MxPresenter") && ((MxPresenter*) *it)->IsEnabled())) {
				m_disabledObjects.insert(*it);
				((MxPresenter*) *it)->Enable(FALSE);
			}
		}

		if (CurrentWorld() && CurrentWorld() == this) {
			ControlManager()->SetPresenterList(NULL);
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

		LegoPathControllerListCursor pathControllerCursor(&m_pathControllerList);

		while (pathControllerCursor.Next(controller)) {
			controller->Enable(FALSE);
			m_disabledObjects.insert(controller);
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
			if (PresentersPending() == TRUE) {
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

	for (MxCoreSet::iterator it = m_objects.begin(); it != m_objects.end(); it++) {
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
