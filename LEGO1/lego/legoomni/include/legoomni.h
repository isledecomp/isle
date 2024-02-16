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
class ViewManager;

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
	enum {
		c_disableInput = 0x01,
		c_disable3d = 0x02,
		c_clearScreen = 0x04
	};

	// SIZE 0x1c
	struct ScriptContainer {
		// FUNCTION: LEGO1 0x1005ac40
		ScriptContainer()
		{
			m_index = -1;
			m_script = NULL;
		}

		ScriptContainer(MxS32 p_index, const char* p_key, MxAtomId* p_script)
		{
			m_index = p_index;

			if (p_key) {
				strcpy(m_key, p_key);
			}

			m_script = p_script;
		}

		// FUNCTION: LEGO1 0x1005ac50
		ScriptContainer& operator=(ScriptContainer& p_container)
		{
			m_index = p_container.m_index;
			strcpy(m_key, p_container.m_key);
			m_script = p_container.m_script;
			return *this;
		}

	private:
		MxS32 m_index;      // 0x00
		char m_key[20];     // 0x04
		MxAtomId* m_script; // 0x18
	};

	LegoOmni();
	~LegoOmni() override; // vtable+00

	MxLong Notify(MxParam& p_param) override; // vtable+04

	// FUNCTION: LEGO1 0x10058aa0
	inline const char* ClassName() const override // vtable+0c
	{
		// STRING: LEGO1 0x100f671c
		return "LegoOmni";
	}

	// FUNCTION: LEGO1 0x10058ab0
	inline MxBool IsA(const char* p_name) const override // vtable+10
	{
		return !strcmp(p_name, LegoOmni::ClassName()) || MxOmni::IsA(p_name);
	}

	void Init() override;                                                                        // vtable+14
	MxResult Create(MxOmniCreateParam& p_param) override;                                        // vtable+18
	void Destroy() override;                                                                     // vtable+1c
	MxResult Start(MxDSAction* p_dsAction) override;                                             // vtable+20
	void DeleteObject(MxDSAction& p_dsAction) override;                                          // vtable+24
	MxBool DoesEntityExist(MxDSAction& p_dsAction) override;                                     // vtable+28
	MxEntity* AddToWorld(const char* p_id, MxS32 p_entityId, MxPresenter* p_presenter) override; // vtable+30
	void NotifyCurrentEntity(MxNotificationParam* p_param) override;                             // vtable+34
	void StartTimer() override;                                                                  // vtable+38
	void StopTimer() override;                                                                   // vtable+3c

	LegoWorld* FindWorld(const MxAtomId& p_atom, MxS32 p_entityid);
	void AddWorld(LegoWorld* p_world);
	void DeleteWorld(LegoWorld* p_world);
	void FUN_1005b4f0(MxBool p_disable, MxU16 p_flags);
	void CreateBackgroundAudio();
	void RemoveWorld(const MxAtomId&, MxLong);
	MxResult RegisterScripts();
	undefined4 FUN_1005b490(char* p_worldName);

	static MxS32 GetCurrPathInfo(LegoPathBoundary**, MxS32&);
	static void CreateInstance();
	static LegoOmni* GetInstance();

	LegoVideoManager* GetVideoManager() { return (LegoVideoManager*) m_videoManager; }
	LegoSoundManager* GetSoundManager() { return (LegoSoundManager*) m_soundManager; }
	LegoInputManager* GetInputManager() { return m_inputMgr; }
	GifManager* GetGifManager() { return m_gifManager; }
	LegoWorld* GetCurrentWorld() { return m_currentWorld; }
	LegoNavController* GetNavController() { return m_navController; }
	IslePathActor* GetCurrentVehicle() { return m_currentVehicle; }
	LegoPlantManager* GetLegoPlantManager() { return m_plantManager; }
	LegoAnimationManager* GetAnimationManager() { return m_animationManager; }
	LegoBuildingManager* GetLegoBuildingManager() { return m_buildingManager; }
	LegoGameState* GetGameState() { return m_gameState; }
	MxBackgroundAudioManager* GetBackgroundAudioManager() { return m_bkgAudioManager; }
	MxTransitionManager* GetTransitionManager() { return m_transitionManager; }
	MxDSAction& GetCurrentAction() { return m_action; }
	LegoUnkSaveDataWriter* GetUnkSaveDataWriter() { return m_saveDataWriter; }
	LegoWorldList* GetWorldList() { return m_worldList; }

	inline void SetNavController(LegoNavController* p_navController) { m_navController = p_navController; }
	inline void SetCurrentWorld(LegoWorld* p_currentWorld) { m_currentWorld = p_currentWorld; }
	inline void SetExit(MxBool p_exit) { m_exit = p_exit; }

	inline void CloseMainWindow() { PostMessageA(m_windowHandle, WM_CLOSE, 0, 0); }

	// SYNTHETIC: LEGO1 0x10058b30
	// LegoOmni::`scalar deleting destructor'

private:
	ScriptContainer* m_scripts;                  // 0x68
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

MxBackgroundAudioManager* BackgroundAudioManager();
LegoGameState* GameState();
const char* GetNoCD_SourceName();
LegoInputManager* InputManager();
LegoOmni* Lego();
LegoEntity* PickEntity(MxLong, MxLong);
LegoROI* PickROI(MxLong, MxLong);
LegoSoundManager* SoundManager();
MxTransitionManager* TransitionManager();
LegoVideoManager* VideoManager();
LegoAnimationManager* AnimationManager();
LegoNavController* NavController();
LegoBuildingManager* BuildingManager();
LegoControlManager* ControlManager();
IslePathActor* CurrentVehicle();
ViewManager* GetViewManager();
LegoPlantManager* PlantManager();
LegoWorld* CurrentWorld();
LegoUnkSaveDataWriter* UnkSaveDataWriter();
GifManager* GetGifManager();
void FUN_10015820(MxBool p_disable, MxU16 p_flags);
void FUN_10015860(const char*, MxU8);
LegoWorld* FindWorld(const MxAtomId& p_atom, MxS32 p_entityid);
MxDSAction& GetCurrentAction();

void PlayMusic(MxU32 p_index);
void SetIsWorldActive(MxBool p_isWorldActive);
void DeleteObjects(MxAtomId* p_id, MxS32 p_first, MxS32 p_last);
void CreateScripts();
void DestroyScripts();
void SetCurrentWorld(LegoWorld* p_world);

#endif // LEGOOMNI_H
