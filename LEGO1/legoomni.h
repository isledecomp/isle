#ifndef LEGOOMNI_H
#define LEGOOMNI_H

#include "compat.h"
#include "mxdsaction.h"
#include "mxomni.h"

class GifManager;
class Isle;
class IslePathActor;
class LegoAnimationManager;
class LegoBuildingManager;
class LegoControlManager;
class LegoEntity;
class LegoGameState;
class LegoInputManager;
class LegoNavController;
class LegoPathBoundary;
class LegoPlantManager;
class LegoROI;
class LegoSoundManager;
class LegoUnkSaveDataWriter;
class LegoVideoManager;
class LegoWorld;
class LegoWorldList;
class MxAtomId;
class MxBackgroundAudioManager;
class MxDSFile;
class MxTransitionManager;
class ViewLODListManager;

extern MxAtomId* g_copterScript;
extern MxAtomId* g_dunecarScript;
extern MxAtomId* g_jetskiScript;
extern MxAtomId* g_racecarScript;
extern MxAtomId* g_carraceScript;
extern MxAtomId* g_carracerScript;
extern MxAtomId* g_jetraceScript;
extern MxAtomId* g_jetracerScript;
extern MxAtomId* g_isleScript;
extern MxAtomId* g_elevbottScript;
extern MxAtomId* g_infodoorScript;
extern MxAtomId* g_infomainScript;
extern MxAtomId* g_infoscorScript;
extern MxAtomId* g_regbookScript;
extern MxAtomId* g_histbookScript;
extern MxAtomId* g_hospitalScript;
extern MxAtomId* g_policeScript;
extern MxAtomId* g_garageScript;
extern MxAtomId* g_act2mainScript;
extern MxAtomId* g_act3Script;
extern MxAtomId* g_jukeboxScript;
extern MxAtomId* g_pz5Script;
extern MxAtomId* g_introScript;
extern MxAtomId* g_testScript;
extern MxAtomId* g_jukeboxwScript;
extern MxAtomId* g_sndAnimScript;
extern MxAtomId* g_creditsScript;
extern MxAtomId* g_nocdSourceName;

// VTABLE: LEGO1 0x100d8638
// SIZE 0x140
class LegoOmni : public MxOmni {
public:
	__declspec(dllexport) void CreateBackgroundAudio();
	__declspec(dllexport) void RemoveWorld(const MxAtomId&, MxLong);
	__declspec(dllexport) static int GetCurrPathInfo(LegoPathBoundary**, MxS32&);
	__declspec(dllexport) static void CreateInstance();
	__declspec(dllexport) static LegoOmni* GetInstance();

	LegoOmni();
	virtual ~LegoOmni(); // vtable+00

	virtual MxLong Notify(MxParam& p_param) override; // vtable+04

	// FUNCTION: LEGO1 0x10058aa0
	inline virtual const char* ClassName() const override // vtable+0c
	{
		// STRING: LEGO1 0x100f671c
		return "LegoOmni";
	}

	// FUNCTION: LEGO1 0x10058ab0
	inline virtual MxBool IsA(const char* p_name) const override // vtable+10
	{
		return !strcmp(p_name, LegoOmni::ClassName()) || MxOmni::IsA(p_name);
	}

	virtual void Init() override;                                                                       // vtable+14
	virtual MxResult Create(MxOmniCreateParam& p_param) override;                                       // vtable+18
	virtual void Destroy() override;                                                                    // vtable+1c
	virtual MxResult Start(MxDSAction* p_dsAction) override;                                            // vtable+20
	virtual void DeleteObject(MxDSAction& p_dsAction) override;                                         // vtable+24
	virtual MxBool DoesEntityExist(MxDSAction& p_dsAction) override;                                    // vtable+28
	virtual MxEntity* FindWorld(const char* p_id, MxS32 p_entityId, MxPresenter* p_presenter) override; // vtable+30
	virtual void NotifyCurrentEntity(MxNotificationParam* p_param) override;                            // vtable+34
	virtual void StartTimer() override;                                                                 // vtable+38
	virtual void StopTimer() override;                                                                  // vtable+3c

	LegoEntity* FindByEntityIdOrAtomId(const MxAtomId& p_atom, MxS32 p_entityid);
	void AddWorld(LegoWorld* p_world);

	LegoVideoManager* GetVideoManager() { return (LegoVideoManager*) m_videoManager; }
	LegoSoundManager* GetSoundManager() { return (LegoSoundManager*) m_soundManager; }

	LegoInputManager* GetInputManager() { return m_inputMgr; }
	GifManager* GetGifManager() { return m_gifManager; }
	LegoWorld* GetCurrentOmniWorld() { return m_currentWorld; }
	LegoNavController* GetNavController() { return m_navController; }
	IslePathActor* GetCurrentVehicle() { return m_currentVehicle; }
	LegoPlantManager* GetLegoPlantManager() { return m_plantManager; }
	LegoAnimationManager* GetAnimationManager() { return m_animationManager; }
	LegoBuildingManager* GetLegoBuildingManager() { return m_buildingManager; }
	LegoGameState* GetGameState() { return m_gameState; }
	MxBackgroundAudioManager* GetBackgroundAudioManager() { return m_bkgAudioManager; }
	MxTransitionManager* GetTransitionManager() { return m_transitionManager; }
	MxDSAction& GetCurrentAction() { return m_action; }

	inline void SetExit(MxBool p_exit) { m_exit = p_exit; };

private:
	undefined4* m_unk0x68;                       // 0x68
	ViewLODListManager* m_viewLODListManager;    // 0x6c
	LegoInputManager* m_inputMgr;                // 0x70
	GifManager* m_gifManager;                    // 0x74
	LegoWorldList* m_worldList;                  // 0x78
	LegoWorld* m_currentWorld;                   // 0x7c
	MxBool m_exit;                               // 0x80
	LegoNavController* m_navController;          // 0x84
	IslePathActor* m_currentVehicle;             // 0x88
	LegoUnkSaveDataWriter* m_saveDataWriter;     // 0x8c
	LegoPlantManager* m_plantManager;            // 0x90
	LegoAnimationManager* m_animationManager;    // 0x94
	LegoBuildingManager* m_buildingManager;      // 0x98
	LegoGameState* m_gameState;                  // 0x9c
	MxDSAction m_action;                         // 0xa0
	MxBackgroundAudioManager* m_bkgAudioManager; // 0x134
	MxTransitionManager* m_transitionManager;    // 0x138
	MxBool m_unk0x13c;                           // 0x13c
};

__declspec(dllexport) MxBackgroundAudioManager* BackgroundAudioManager();
__declspec(dllexport) MxDSObject* CreateStreamObject(MxDSFile*, MxS16);
__declspec(dllexport) LegoGameState* GameState();
__declspec(dllexport) const char* GetNoCD_SourceName();
__declspec(dllexport) LegoInputManager* InputManager();
__declspec(dllexport) LegoOmni* Lego();
__declspec(dllexport) void MakeSourceName(char*, const char*);
__declspec(dllexport) LegoEntity* PickEntity(MxLong, MxLong);
__declspec(dllexport) LegoROI* PickROI(MxLong, MxLong);
__declspec(dllexport) void SetOmniUserMessage(void (*)(const char*, int));
__declspec(dllexport) LegoSoundManager* SoundManager();
__declspec(dllexport) MxResult Start(MxDSAction*);
__declspec(dllexport) MxTransitionManager* TransitionManager();
__declspec(dllexport) LegoVideoManager* VideoManager();

LegoAnimationManager* AnimationManager();
LegoBuildingManager* BuildingManager();
LegoControlManager* ControlManager();
IslePathActor* GetCurrentVehicle();
LegoPlantManager* PlantManager();
MxBool KeyValueStringParse(char*, const char*, const char*);
LegoWorld* GetCurrentWorld();
GifManager* GetGifManager();
void FUN_10015820(MxU32, MxU32);
LegoEntity* FindEntityByAtomIdOrEntityId(const MxAtomId& p_atom, MxS32 p_entityid);
MxDSAction& GetCurrentAction();

MxBool FUN_100b6e10(
	MxS32 p_bitmapWidth,
	MxS32 p_bitmapHeight,
	MxS32 p_videoParamWidth,
	MxS32 p_videoParamHeight,
	MxS32* p_left,
	MxS32* p_top,
	MxS32* p_right,
	MxS32* p_bottom,
	MxS32* p_width,
	MxS32* p_height
);

void PlayMusic(MxU32 p_index);
void SetIsWorldActive(MxBool p_isWorldActive);
void RegisterScripts();
void UnregisterScripts();

#endif // LEGOOMNI_H
