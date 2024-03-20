#include "misc.h"

#include "mxbackgroundaudiomanager.h"
#include "mxmisc.h"

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
LegoVideoManager* VideoManager()
{
	return LegoOmni::GetInstance()->GetVideoManager();
}

// FUNCTION: LEGO1 0x10015730
MxBackgroundAudioManager* BackgroundAudioManager()
{
	return LegoOmni::GetInstance()->GetBackgroundAudioManager();
}

// FUNCTION: LEGO1 0x10015740
LegoInputManager* InputManager()
{
	return LegoOmni::GetInstance()->GetInputManager();
}

// FUNCTION: LEGO1 0x10015750
LegoControlManager* ControlManager()
{
	return LegoOmni::GetInstance()->GetInputManager()->GetControlManager();
}

// FUNCTION: LEGO1 0x10015760
LegoGameState* GameState()
{
	return LegoOmni::GetInstance()->GetGameState();
}

// FUNCTION: LEGO1 0x10015770
LegoAnimationManager* AnimationManager()
{
	return LegoOmni::GetInstance()->GetAnimationManager();
}

// FUNCTION: LEGO1 0x10015780
LegoNavController* NavController()
{
	return LegoOmni::GetInstance()->GetNavController();
}

// FUNCTION: LEGO1 0x10015790
IslePathActor* CurrentActor()
{
	return LegoOmni::GetInstance()->GetCurrentActor();
}

// FUNCTION: LEGO1 0x100157a0
LegoWorld* CurrentWorld()
{
	return LegoOmni::GetInstance()->GetCurrentWorld();
}

// FUNCTION: LEGO1 0x100157b0
LegoCharacterManager* CharacterManager()
{
	return LegoOmni::GetInstance()->GetCharacterManager();
}

// FUNCTION: LEGO1 0x100157c0
ViewManager* GetViewManager()
{
	return VideoManager()->Get3DManager()->GetLego3DView()->GetViewManager();
}

// FUNCTION: LEGO1 0x100157e0
LegoPlantManager* PlantManager()
{
	return LegoOmni::GetInstance()->GetLegoPlantManager();
}

// FUNCTION: LEGO1 0x100157f0
LegoBuildingManager* BuildingManager()
{
	return LegoOmni::GetInstance()->GetLegoBuildingManager();
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
void FUN_10015820(MxBool p_disable, MxU16 p_flags)
{
	LegoOmni::GetInstance()->FUN_1005b4f0(p_disable, p_flags);
}

// FUNCTION: LEGO1 0x10015840
LegoROI* FindROI(const char* p_name)
{
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
void SetCurrentActor(IslePathActor* p_currentActor)
{
	LegoOmni::GetInstance()->SetCurrentActor(p_currentActor);
}

// FUNCTION: LEGO1 0x100158b0
void DeleteAction()
{
	LegoOmni::GetInstance()->DeleteAction();
}

// FUNCTION: LEGO1 0x100158c0
LegoWorld* FindWorld(const MxAtomId& p_atom, MxS32 p_entityid)
{
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
MxTransitionManager* TransitionManager()
{
	return LegoOmni::GetInstance()->GetTransitionManager();
}

// FUNCTION: LEGO1 0x10015910
void PlayMusic(JukeboxScript::Script p_script)
{
	MxDSAction action;
	action.SetAtomId(*g_jukeboxScript);
	action.SetObjectId(p_script);

	LegoOmni::GetInstance()->GetBackgroundAudioManager()->PlayMusic(action, 5, 4);
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
