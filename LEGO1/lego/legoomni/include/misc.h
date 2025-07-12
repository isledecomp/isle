#ifndef MISC_H
#define MISC_H

#include "compat.h"
#include "decomp.h"
// Long include path due to dependency of misc library on LegoOmni
#include "lego/legoomni/include/actions/actionsfwd.h"
#include "mxtypes.h"

class LegoAnimationManager;
class LegoBuildingManager;
class LegoCharacterManager;
class LegoControlManager;
class LegoGameState;
class LegoInputManager;
class LegoNavController;
class LegoOmni;
class LegoPathActor;
class LegoPlantManager;
class LegoROI;
class LegoSoundManager;
class LegoTextureContainer;
class LegoVideoManager;
class LegoWorld;
class MxAtomId;
class MxBackgroundAudioManager;
class MxDSAction;
class MxTransitionManager;
class ViewLODListManager;
class ViewManager;

extern MxBool g_isWorldActive;

LegoOmni* Lego();
LegoSoundManager* SoundManager();
LegoVideoManager* VideoManager();
MxBackgroundAudioManager* BackgroundAudioManager();
LegoInputManager* InputManager();
LegoControlManager* ControlManager();
LegoGameState* GameState();
LegoAnimationManager* AnimationManager();
LegoNavController* NavController();
LegoPathActor* UserActor();
LegoWorld* CurrentWorld();
LegoCharacterManager* CharacterManager();
ViewManager* GetViewManager();
LegoPlantManager* PlantManager();
LegoBuildingManager* BuildingManager();
LegoTextureContainer* TextureContainer();
ViewLODListManager* GetViewLODListManager();
void Disable(MxBool p_disable, MxU16 p_flags);
LegoROI* FindROI(const char* p_name);
void SetROIVisible(const char* p_name, MxBool p_visible);
void SetUserActor(LegoPathActor* p_userActor);
MxResult StartActionIfUnknown0x13c(MxDSAction& p_dsAction);
void DeleteAction();
LegoWorld* FindWorld(const MxAtomId& p_atom, MxS32 p_entityid);
MxDSAction& GetCurrentAction();
void SetCurrentWorld(LegoWorld* p_world);
MxTransitionManager* TransitionManager();
void PlayMusic(JukeboxScript::Script p_objectId);
void SetIsWorldActive(MxBool p_isWorldActive);
void DeleteObjects(MxAtomId* p_id, MxS32 p_first, MxS32 p_last);

#endif // MISC_H
