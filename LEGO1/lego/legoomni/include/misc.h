#ifndef MISC_H
#define MISC_H

#include "compat.h"
#include "decomp.h"
#include "mxtypes.h"

class IslePathActor;
class LegoAnimationManager;
class LegoBuildingManager;
class LegoCharacterManager;
class LegoControlManager;
class LegoGameState;
class LegoInputManager;
class LegoNavController;
class LegoOmni;
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

namespace JukeboxScript
{
#ifdef COMPAT_MODE
enum Script : int;
#else
enum Script;
#endif
} // namespace JukeboxScript

extern MxBool g_isWorldActive;

LegoOmni* Lego();
LegoInputManager* InputManager();
LegoSoundManager* SoundManager();
MxBackgroundAudioManager* BackgroundAudioManager();
LegoGameState* GameState();
MxTransitionManager* TransitionManager();
LegoVideoManager* VideoManager();
LegoAnimationManager* AnimationManager();
LegoNavController* NavController();
LegoBuildingManager* BuildingManager();
LegoControlManager* ControlManager();
IslePathActor* CurrentActor();
ViewManager* GetViewManager();
LegoPlantManager* PlantManager();
LegoWorld* CurrentWorld();
LegoCharacterManager* CharacterManager();
LegoTextureContainer* TextureContainer();
ViewLODListManager* GetViewLODListManager();
LegoWorld* FindWorld(const MxAtomId& p_atom, MxS32 p_entityid);
LegoROI* FindROI(const char* p_name);
MxDSAction& GetCurrentAction();
void PlayMusic(JukeboxScript::Script p_script);
void SetIsWorldActive(MxBool p_isWorldActive);
void DeleteObjects(MxAtomId* p_id, MxS32 p_first, MxS32 p_last);
void SetCurrentWorld(LegoWorld* p_world);
void FUN_10015820(MxBool p_disable, MxU16 p_flags);
void SetROIUnknown0x0c(const char* p_name, undefined p_unk0x0c);
void SetCurrentActor(IslePathActor* p_currentActor);

#endif // MISC_H
