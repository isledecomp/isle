#ifndef LEGOMAIN_H
#define LEGOMAIN_H

#include "compat.h"
#include "mxdsaction.h"
#include "mxomni.h"

class Isle;
class LegoAnimationManager;
class LegoBuildingManager;
class LegoCharacterManager;
class LegoEntity;
class LegoGameState;
class LegoInputManager;
class LegoNavController;
class LegoPathActor;
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
// VTABLE: BETA10 0x101bc8b8
// SIZE 0x140
class LegoOmni : public MxOmni {
public:
	enum {
		c_disableInput = 0x01,
		c_disable3d = 0x02,
		c_clearScreen = 0x04
	};

	enum World {
		e_undefined = -1,
		e_act1 = 0,
		e_imain,
		e_icube,
		e_ireg,
		e_ielev,
		e_iisle,
		e_hosp,
		e_police,
		e_gmain,
		e_bldh,
		e_bldd,
		e_bldj,
		e_bldr,
		e_racc,
		e_racj,
		e_act2,
		e_act3,
		e_test,
		e_numWorlds = e_test + 2 // count e_undefined
	};

	// SIZE 0x1c
	struct WorldContainer {
		// FUNCTION: LEGO1 0x1005ac40
		WorldContainer()
		{
			m_id = e_undefined;
			m_atomId = NULL;
		}

		WorldContainer(World p_id, const char* p_key, MxAtomId* p_atomId)
		{
			m_id = p_id;

			if (p_key) {
				strcpy(m_key, p_key);
			}

			m_atomId = p_atomId;
		}

		// FUNCTION: LEGO1 0x1005ac50
		WorldContainer& operator=(const WorldContainer& p_container)
		{
			m_id = p_container.m_id;
			strcpy(m_key, p_container.m_key);
			m_atomId = p_container.m_atomId;
			return *this;
		}

		World GetId() { return m_id; }
		const char* GetKey() { return m_key; }

		World m_id;         // 0x00
		char m_key[20];     // 0x04
		MxAtomId* m_atomId; // 0x18
	};

	LegoOmni();
	~LegoOmni() override;

	MxLong Notify(MxParam& p_param) override; // vtable+0x04

	// FUNCTION: LEGO1 0x10058aa0
	// FUNCTION: BETA10 0x1008f830
	const char* ClassName() const override // vtable+0x0c
	{
		// STRING: LEGO1 0x100f671c
		return "LegoOmni";
	}

	// FUNCTION: LEGO1 0x10058ab0
	MxBool IsA(const char* p_name) const override // vtable+0x10
	{
		return !strcmp(p_name, LegoOmni::ClassName()) || MxOmni::IsA(p_name);
	}

	void Init() override;                                                                        // vtable+0x14
	MxResult Create(MxOmniCreateParam& p_param) override;                                        // vtable+0x18
	void Destroy() override;                                                                     // vtable+0x1c
	MxResult Start(MxDSAction* p_dsAction) override;                                             // vtable+0x20
	void DeleteObject(MxDSAction& p_dsAction) override;                                          // vtable+0x24
	MxBool DoesEntityExist(MxDSAction& p_dsAction) override;                                     // vtable+0x28
	MxEntity* AddToWorld(const char* p_id, MxS32 p_entityId, MxPresenter* p_presenter) override; // vtable+0x30
	void NotifyCurrentEntity(const MxNotificationParam& p_param) override;                       // vtable+0x34
	void Pause() override;                                                                       // vtable+0x38
	void Resume() override;                                                                      // vtable+0x3c

	LegoWorld* FindWorld(const MxAtomId& p_atom, MxS32 p_entityid);
	LegoROI* FindROI(const char* p_name);
	void AddWorld(LegoWorld* p_world);
	void DeleteWorld(LegoWorld* p_world);
	void FUN_1005b4f0(MxBool p_disable, MxU16 p_flags);
	void CreateBackgroundAudio();
	void RemoveWorld(const MxAtomId& p_atom, MxLong p_objectId);
	MxResult RegisterWorlds();
	const char* GetWorldName(LegoOmni::World p_id);
	MxAtomId* GetWorldAtom(LegoOmni::World p_id);
	World GetWorldId(const char* p_key);
	void DeleteAction();

	static MxS32 GetCurrPathInfo(LegoPathBoundary**, MxS32&);
	static void CreateInstance();
	static LegoOmni* GetInstance();

	LegoVideoManager* GetVideoManager() { return (LegoVideoManager*) m_videoManager; }
	LegoSoundManager* GetSoundManager() { return (LegoSoundManager*) m_soundManager; }

	// FUNCTION: BETA10 0x1009e7a0
	LegoInputManager* GetInputManager() { return m_inputManager; }

	LegoTextureContainer* GetTextureContainer() { return m_textureContainer; }
	ViewLODListManager* GetViewLODListManager() { return m_viewLODListManager; }
	LegoWorld* GetCurrentWorld() { return m_currentWorld; }
	LegoNavController* GetNavController() { return m_navController; }
	LegoPathActor* GetUserActor() { return m_userActor; }

	// FUNCTION: BETA10 0x100e53a0
	LegoPlantManager* GetPlantManager() { return m_plantManager; }

	LegoAnimationManager* GetAnimationManager() { return m_animationManager; }

	// FUNCTION: BETA10 0x100e53d0
	LegoBuildingManager* GetBuildingManager() { return m_buildingManager; }

	// FUNCTION: BETA10 0x100e52b0
	LegoGameState* GetGameState() { return m_gameState; }

	MxBackgroundAudioManager* GetBackgroundAudioManager() { return m_bkgAudioManager; }
	MxTransitionManager* GetTransitionManager() { return m_transitionManager; }
	MxDSAction& GetCurrentAction() { return m_action; }
	LegoCharacterManager* GetCharacterManager() { return m_characterManager; }
	LegoWorldList* GetWorldList() { return m_worldList; }

	void SetNavController(LegoNavController* p_navController) { m_navController = p_navController; }
	void SetUserActor(LegoPathActor* p_userActor) { m_userActor = p_userActor; }
	void SetCurrentWorld(LegoWorld* p_currentWorld) { m_currentWorld = p_currentWorld; }

	// FUNCTION: BETA10 0x100d55c0
	void SetExit(MxBool p_exit) { m_exit = p_exit; }

	MxResult StartActionIfUnknown0x13c(MxDSAction& p_dsAction) { return m_unk0x13c ? Start(&p_dsAction) : SUCCESS; }
	void SetUnknown13c(MxBool p_unk0x13c) { m_unk0x13c = p_unk0x13c; }

	void CloseMainWindow() { PostMessageA(m_windowHandle, WM_CLOSE, 0, 0); }

	// SYNTHETIC: LEGO1 0x10058b30
	// LegoOmni::`scalar deleting destructor'

private:
	WorldContainer* m_worlds;                    // 0x68
	ViewLODListManager* m_viewLODListManager;    // 0x6c
	LegoInputManager* m_inputManager;            // 0x70
	LegoTextureContainer* m_textureContainer;    // 0x74
	LegoWorldList* m_worldList;                  // 0x78
	LegoWorld* m_currentWorld;                   // 0x7c
	MxBool m_exit;                               // 0x80
	LegoNavController* m_navController;          // 0x84
	LegoPathActor* m_userActor;                  // 0x88
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
