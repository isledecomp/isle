#ifndef LEGOOMNI_H
#define LEGOOMNI_H

#include "compat.h"
#include "mxdsaction.h"
#include "mxomni.h"

class GifManager;
class Isle;
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
class MxAtomId;
class MxBackgroundAudioManager;
class MxDSFile;
class MxTransitionManager;

// VTABLE 0x100d8638
// SIZE: 0x140
class LegoOmni : public MxOmni {
public:
	__declspec(dllexport) void CreateBackgroundAudio();
	__declspec(dllexport) void RemoveWorld(const MxAtomId& p1, MxLong p2);
	__declspec(dllexport) static int GetCurrPathInfo(LegoPathBoundary**, int&);
	__declspec(dllexport) static void CreateInstance();
	__declspec(dllexport) static LegoOmni* GetInstance();

	LegoOmni();
	virtual ~LegoOmni(); // vtable+00

	virtual MxLong Notify(MxParam& p) override; // vtable+04

	// OFFSET: LEGO1 0x10058aa0
	inline virtual const char* ClassName() const override // vtable+0c
	{
		// 0x100f671c
		return "LegoOmni";
	}

	// OFFSET: LEGO1 0x10058ab0
	inline virtual MxBool IsA(const char* name) const override // vtable+10
	{
		return !strcmp(name, LegoOmni::ClassName()) || MxOmni::IsA(name);
	}

	virtual void Init() override;                                            // vtable+14
	virtual MxResult Create(MxOmniCreateParam& p) override;                  // vtable+18
	virtual void Destroy() override;                                         // vtable+1c
	virtual MxResult Start(MxDSAction* action) override;                     // vtable+20
	virtual MxResult DeleteObject(MxDSAction& ds) override;                  // vtable+24
	virtual MxBool DoesEntityExist(MxDSAction& ds) override;                 // vtable+28
	virtual LegoWorld* Vtable0x30(const char* p_id, int p_entityId, MxCore* p_presenter) override;                    // vtable+30
	virtual void NotifyCurrentEntity(MxNotificationParam* p_param) override; // vtable+34
	virtual void StartTimer() override;                                      // vtable+38
	virtual void StopTimer() override;                                       // vtable+3c

	LegoEntity* FindByEntityIdOrAtomId(MxAtomId& p_atom, int p_entityid);

	LegoVideoManager* GetVideoManager() { return (LegoVideoManager*) m_videoManager; }
	LegoSoundManager* GetSoundManager() { return (LegoSoundManager*) m_soundManager; }

	LegoInputManager* GetInputManager() { return m_inputMgr; }
	GifManager* GetGifManager() { return m_gifManager; }
	LegoWorld* GetCurrentWorld() { return m_currentWorld; }
	LegoNavController* GetNavController() { return m_navController; }
	LegoWorld* GetCurrentVehicle() { return m_currentVehicle; }
	LegoPlantManager* GetLegoPlantManager() { return m_plantManager; }
	LegoAnimationManager* GetAnimationManager() { return m_animationManager; }
	LegoBuildingManager* GetLegoBuildingManager() { return m_buildingManager; }
	LegoGameState* GetGameState() { return m_gameState; }
	MxBackgroundAudioManager* GetBackgroundAudioManager() { return m_bkgAudioManager; }
	MxTransitionManager* GetTransitionManager() { return m_transitionManager; }

private:
	undefined4 m_unk68;
	undefined4 m_unk6c;
	LegoInputManager* m_inputMgr; // 0x70
	GifManager* m_gifManager;
	undefined4 m_unk78;
	LegoWorld* m_currentWorld;
	MxBool m_unk80;
	LegoNavController* m_navController; // 0x84
	LegoWorld* m_currentVehicle;        // 0x88
	LegoUnkSaveDataWriter* m_unkLegoSaveDataWriter;
	LegoPlantManager* m_plantManager; // 0x90
	LegoAnimationManager* m_animationManager;
	LegoBuildingManager* m_buildingManager; // 0x98
	LegoGameState* m_gameState;             // 0x9c
	MxDSAction m_action;
	MxBackgroundAudioManager* m_bkgAudioManager; // 0x134
	MxTransitionManager* m_transitionManager;    // 0x138
	MxBool m_unk13c;
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
LegoWorld* GetCurrentVehicle();
LegoPlantManager* PlantManager();
MxBool KeyValueStringParse(char*, const char*, const char*);
LegoWorld* GetCurrentWorld();
GifManager* GetGifManager();

#endif // LEGOOMNI_H
