#ifndef LEGOMAIN_H
#define LEGOMAIN_H

#include "compat.h"
#include "mxdsaction.h"
#include "mxomni.h"

class Isle;
class IslePathActor;
class LegoAnimationManager;
class LegoBuildingManager;
class LegoCharacterManager;
class LegoEntity;
class LegoGameState;
class LegoInputManager;
class LegoNavController;
class LegoPathBoundary;
class LegoPlantManager;
class LegoROI;
class LegoSoundManager;
class LegoTextureContainer;
class LegoVideoManager;
class LegoWorld;
class LegoWorldList;
class MxAtomId;
class MxBackgroundAudioManager;
class MxTransitionManager;
class ViewLODListManager;

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
			m_atomId = NULL;
		}

		ScriptContainer(MxS32 p_index, const char* p_key, MxAtomId* p_atomId)
		{
			m_index = p_index;

			if (p_key) {
				strcpy(m_key, p_key);
			}

			m_atomId = p_atomId;
		}

		// FUNCTION: LEGO1 0x1005ac50
		ScriptContainer& operator=(const ScriptContainer& p_container)
		{
			m_index = p_container.m_index;
			strcpy(m_key, p_container.m_key);
			m_atomId = p_container.m_atomId;
			return *this;
		}

		inline MxS32 GetIndex() { return m_index; }
		inline const char* GetKey() { return m_key; }

		MxS32 m_index;      // 0x00
		char m_key[20];     // 0x04
		MxAtomId* m_atomId; // 0x18
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
	void NotifyCurrentEntity(const MxNotificationParam& p_param) override;                       // vtable+34
	void StartTimer() override;                                                                  // vtable+38
	void StopTimer() override;                                                                   // vtable+3c

	LegoWorld* FindWorld(const MxAtomId& p_atom, MxS32 p_entityid);
	LegoROI* FindROI(const char* p_name);
	void AddWorld(LegoWorld* p_world);
	void DeleteWorld(LegoWorld* p_world);
	void FUN_1005b4f0(MxBool p_disable, MxU16 p_flags);
	void CreateBackgroundAudio();
	void RemoveWorld(const MxAtomId& p_atom, MxLong p_objectId);
	MxResult RegisterScripts();
	const char* GetScriptName(MxU32 p_index);
	MxAtomId* GetScriptAtom(MxU32 p_index);
	MxS32 GetScriptIndex(const char* p_key);
	void DeleteAction();

	static MxS32 GetCurrPathInfo(LegoPathBoundary**, MxS32&);
	static void CreateInstance();
	static LegoOmni* GetInstance();

	LegoVideoManager* GetVideoManager() { return (LegoVideoManager*) m_videoManager; }
	LegoSoundManager* GetSoundManager() { return (LegoSoundManager*) m_soundManager; }
	LegoInputManager* GetInputManager() { return m_inputManager; }
	LegoTextureContainer* GetTextureContainer() { return m_textureContainer; }
	ViewLODListManager* GetViewLODListManager() { return m_viewLODListManager; }
	LegoWorld* GetCurrentWorld() { return m_currentWorld; }
	LegoNavController* GetNavController() { return m_navController; }
	IslePathActor* GetCurrentActor() { return m_currentActor; }
	LegoPlantManager* GetLegoPlantManager() { return m_plantManager; }
	LegoAnimationManager* GetAnimationManager() { return m_animationManager; }
	LegoBuildingManager* GetLegoBuildingManager() { return m_buildingManager; }
	LegoGameState* GetGameState() { return m_gameState; }
	MxBackgroundAudioManager* GetBackgroundAudioManager() { return m_bkgAudioManager; }
	MxTransitionManager* GetTransitionManager() { return m_transitionManager; }
	MxDSAction& GetCurrentAction() { return m_action; }
	LegoCharacterManager* GetCharacterManager() { return m_characterManager; }
	LegoWorldList* GetWorldList() { return m_worldList; }

	inline void SetNavController(LegoNavController* p_navController) { m_navController = p_navController; }
	inline void SetCurrentActor(IslePathActor* p_currentActor) { m_currentActor = p_currentActor; }
	inline void SetCurrentWorld(LegoWorld* p_currentWorld) { m_currentWorld = p_currentWorld; }
	inline void SetExit(MxBool p_exit) { m_exit = p_exit; }
	inline MxResult StartActionIfUnknown0x13c(MxDSAction& p_dsAction)
	{
		return m_unk0x13c ? Start(&p_dsAction) : SUCCESS;
	}
	inline void SetUnknown13c(MxBool p_unk0x13c) { m_unk0x13c = p_unk0x13c; }

	inline void CloseMainWindow() { PostMessageA(m_windowHandle, WM_CLOSE, 0, 0); }

	// SYNTHETIC: LEGO1 0x10058b30
	// LegoOmni::`scalar deleting destructor'

private:
	ScriptContainer* m_scripts;                  // 0x68
	ViewLODListManager* m_viewLODListManager;    // 0x6c
	LegoInputManager* m_inputManager;            // 0x70
	LegoTextureContainer* m_textureContainer;    // 0x74
	LegoWorldList* m_worldList;                  // 0x78
	LegoWorld* m_currentWorld;                   // 0x7c
	MxBool m_exit;                               // 0x80
	LegoNavController* m_navController;          // 0x84
	IslePathActor* m_currentActor;               // 0x88
	LegoCharacterManager* m_characterManager;    // 0x8c
	LegoPlantManager* m_plantManager;            // 0x90
	LegoAnimationManager* m_animationManager;    // 0x94
	LegoBuildingManager* m_buildingManager;      // 0x98
	LegoGameState* m_gameState;                  // 0x9c
	MxDSAction m_action;                         // 0xa0
	MxBackgroundAudioManager* m_bkgAudioManager; // 0x134
	MxTransitionManager* m_transitionManager;    // 0x138

public:
	MxBool m_unk0x13c; // 0x13c
};

#endif // LEGOMAIN_H
