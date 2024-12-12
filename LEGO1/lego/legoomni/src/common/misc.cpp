#include "misc.h"

#include "3dmanager/lego3dmanager.h"
#include "legoinputmanager.h"
#include "legomain.h"
#include "legovideomanager.h"
#include "mxbackgroundaudiomanager.h"
#include "mxmisc.h"
#include "roi/legoroi.h"
#include "scripts.h"

// GLOBAL: LEGO1 0x100f4c58
MxBool g_isWorldActive = TRUE;

// FUNCTION: LEGO1 0x10015700
LegoOmni* Lego()
{
	return LegoOmni::GetInstance();
}

// FUNCTION: LEGO1 0x10015710
LegoSoundManager* SoundManager()
{
	return LegoOmni::GetInstance()->GetSoundManager();
}

// FUNCTION: LEGO1 0x10015720
// FUNCTION: BETA10 0x100e4807
LegoVideoManager* VideoManager()
{
	assert(LegoOmni::GetInstance());
	return LegoOmni::GetInstance()->GetVideoManager();
}

// FUNCTION: LEGO1 0x10015730
// FUNCTION: BETA10 0x100e484e
MxBackgroundAudioManager* BackgroundAudioManager()
{
	assert(LegoOmni::GetInstance());
	return LegoOmni::GetInstance()->GetBackgroundAudioManager();
}

// FUNCTION: LEGO1 0x10015740
// FUNCTION: BETA10 0x100e4895
LegoInputManager* InputManager()
{
	assert(LegoOmni::GetInstance());
	return LegoOmni::GetInstance()->GetInputManager();
}

// FUNCTION: LEGO1 0x10015750
// FUNCTION: BETA10 0x100e48dc
LegoControlManager* ControlManager()
{
	assert(LegoOmni::GetInstance());
	return LegoOmni::GetInstance()->GetInputManager()->GetControlManager();
}

// FUNCTION: LEGO1 0x10015760
// FUNCTION: BETA10 0x100e492a
LegoGameState* GameState()
{
	assert(LegoOmni::GetInstance());
	return LegoOmni::GetInstance()->GetGameState();
}

// FUNCTION: LEGO1 0x10015770
// FUNCTION: BETA10 0x100e4971
LegoAnimationManager* AnimationManager()
{
	assert(LegoOmni::GetInstance());
	return LegoOmni::GetInstance()->GetAnimationManager();
}

// FUNCTION: LEGO1 0x10015780
// FUNCTION: BETA10 0x100e49b8
LegoNavController* NavController()
{
	assert(LegoOmni::GetInstance());
	return LegoOmni::GetInstance()->GetNavController();
}

// FUNCTION: LEGO1 0x10015790
// FUNCTION: BETA10 0x100e49ff
LegoPathActor* UserActor()
{
	assert(LegoOmni::GetInstance());
	return LegoOmni::GetInstance()->GetUserActor();
}

// FUNCTION: LEGO1 0x100157a0
// FUNCTION: BETA10 0x100e4a46
LegoWorld* CurrentWorld()
{
	assert(LegoOmni::GetInstance());
	return LegoOmni::GetInstance()->GetCurrentWorld();
}

// FUNCTION: LEGO1 0x100157b0
// FUNCTION: BETA10 0x100e4a8d
LegoCharacterManager* CharacterManager()
{
	assert(LegoOmni::GetInstance());
	return LegoOmni::GetInstance()->GetCharacterManager();
}

// FUNCTION: LEGO1 0x100157c0
ViewManager* GetViewManager()
{
	return VideoManager()->Get3DManager()->GetLego3DView()->GetViewManager();
}

// FUNCTION: LEGO1 0x100157e0
// FUNCTION: BETA10 0x100e4b29
LegoPlantManager* PlantManager()
{
	assert(LegoOmni::GetInstance());
	return LegoOmni::GetInstance()->GetPlantManager();
}

// FUNCTION: LEGO1 0x100157f0
// FUNCTION: BETA10 0x100e4b70
LegoBuildingManager* BuildingManager()
{
	assert(LegoOmni::GetInstance());
	return LegoOmni::GetInstance()->GetBuildingManager();
}

// FUNCTION: LEGO1 0x10015800
LegoTextureContainer* TextureContainer()
{
	return LegoOmni::GetInstance()->GetTextureContainer();
}

// FUNCTION: LEGO1 0x10015810
ViewLODListManager* GetViewLODListManager()
{
	return LegoOmni::GetInstance()->GetViewLODListManager();
}

// FUNCTION: LEGO1 0x10015820
// FUNCTION: BETA10 0x100e4c92
void FUN_10015820(MxBool p_disable, MxU16 p_flags)
{
	assert(LegoOmni::GetInstance());
	LegoOmni::GetInstance()->FUN_1005b4f0(p_disable, p_flags);
}

// FUNCTION: LEGO1 0x10015840
// FUNCTION: BETA10 0x100e4ce4
LegoROI* FindROI(const char* p_name)
{
	assert(LegoOmni::GetInstance());
	return LegoOmni::GetInstance()->FindROI(p_name);
}

// FUNCTION: LEGO1 0x10015860
void SetROIVisible(const char* p_name, MxBool p_visible)
{
	LegoROI* roi = FindROI(p_name);

	if (roi) {
		roi->SetVisibility(p_visible);
	}
}

// FUNCTION: LEGO1 0x10015880
void SetUserActor(LegoPathActor* p_userActor)
{
	LegoOmni::GetInstance()->SetUserActor(p_userActor);
}

// FUNCTION: LEGO1 0x10015890
// FUNCTION: BETA10 0x100e4d80
MxResult StartActionIfUnknown0x13c(MxDSAction& p_dsAction)
{
	return LegoOmni::GetInstance()->StartActionIfUnknown0x13c(p_dsAction);
}

// FUNCTION: LEGO1 0x100158b0
void DeleteAction()
{
	LegoOmni::GetInstance()->DeleteAction();
}

// FUNCTION: LEGO1 0x100158c0
// FUNCTION: BETA10 0x100e4e18
LegoWorld* FindWorld(const MxAtomId& p_atom, MxS32 p_entityid)
{
	assert(LegoOmni::GetInstance());
	return LegoOmni::GetInstance()->FindWorld(p_atom, p_entityid);
}

// FUNCTION: LEGO1 0x100158e0
MxDSAction& GetCurrentAction()
{
	return LegoOmni::GetInstance()->GetCurrentAction();
}

// FUNCTION: LEGO1 0x100158f0
void SetCurrentWorld(LegoWorld* p_world)
{
	LegoOmni::GetInstance()->SetCurrentWorld(p_world);
}

// FUNCTION: LEGO1 0x10015900
// FUNCTION: BETA10 0x100e4f02
MxTransitionManager* TransitionManager()
{
	assert(LegoOmni::GetInstance());
	return LegoOmni::GetInstance()->GetTransitionManager();
}

// FUNCTION: LEGO1 0x10015910
void PlayMusic(JukeboxScript::Script p_objectId)
{
	MxDSAction action;
	action.SetAtomId(*g_jukeboxScript);
	action.SetObjectId(p_objectId);

	LegoOmni::GetInstance()->GetBackgroundAudioManager()->PlayMusic(action, 5, MxPresenter::e_repeating);
}

// FUNCTION: LEGO1 0x100159c0
void SetIsWorldActive(MxBool p_isWorldActive)
{
	if (!p_isWorldActive) {
		LegoOmni::GetInstance()->GetInputManager()->SetCamera(NULL);
	}
	g_isWorldActive = p_isWorldActive;
}

// FUNCTION: LEGO1 0x100159e0
void DeleteObjects(MxAtomId* p_id, MxS32 p_first, MxS32 p_last)
{
	MxDSAction action;

	action.SetAtomId(*p_id);
	action.SetUnknown24(-2);

	for (MxS32 first = p_first, last = p_last; first <= last; first++) {
		action.SetObjectId(first);
		DeleteObject(action);
	}
}
