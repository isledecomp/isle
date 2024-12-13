#ifndef ISLEPATHACTOR_H
#define ISLEPATHACTOR_H

#include "legogamestate.h"
#include "legopathactor.h"
#include "mxtypes.h"
#include "roi/legoroi.h"

class LegoControlManagerNotificationParam;
class LegoEndAnimNotificationParam;
class LegoWorld;
class LegoPathStructNotificationParam;

// VTABLE: LEGO1 0x100d4398
// SIZE 0x160
class IslePathActor : public LegoPathActor {
public:
	enum {
		c_LOCATIONS_NUM = 29
	};

	enum {
		c_spawnBit1 = 0x01,
		c_playMusic = 0x02,
		c_spawnBit3 = 0x04
	};

	// SIZE 0x38
	struct SpawnLocation {
		SpawnLocation() {}

		// FUNCTION: LEGO1 0x1001b1b0
		SpawnLocation(
			LegoGameState::Area p_area,
			MxAtomId* p_script,
			MxS32 p_entityId,
			const char* p_name,
			MxS16 p_src,
			float p_srcScale,
			MxS16 p_dest,
			float p_destScale,
			MxU32 p_location,
			JukeboxScript::Script p_music
		)
		{
			m_area = p_area;
			m_script = p_script;
			m_entityId = p_entityId;
			strcpy(m_name, p_name);
			m_src = p_src;
			m_srcScale = p_srcScale;
			m_dest = p_dest;
			m_destScale = p_destScale;
			m_location = p_location;
			m_music = p_music;
		}

		// FUNCTION: LEGO1 0x1001b230
		SpawnLocation& operator=(const SpawnLocation& p_location)
		{
			m_area = p_location.m_area;
			m_script = p_location.m_script;
			m_entityId = p_location.m_entityId;
			strcpy(m_name, p_location.m_name);
			m_src = p_location.m_src;
			m_srcScale = p_location.m_srcScale;
			m_dest = p_location.m_dest;
			m_destScale = p_location.m_destScale;
			m_location = p_location.m_location;
			m_music = p_location.m_music;
			return *this;
		}

		LegoGameState::Area m_area;    // 0x00
		MxAtomId* m_script;            // 0x04
		MxS32 m_entityId;              // 0x08
		char m_name[20];               // 0x0c
		MxS16 m_src;                   // 0x20
		float m_srcScale;              // 0x24
		MxS16 m_dest;                  // 0x28
		float m_destScale;             // 0x2c
		MxU32 m_location;              // 0x30
		JukeboxScript::Script m_music; // 0x34
	};

	IslePathActor();

	// FUNCTION: LEGO1 0x10002e10
	~IslePathActor() override { IslePathActor::Destroy(TRUE); }

	MxLong Notify(MxParam& p_param) override; // vtable+0x04

	// FUNCTION: LEGO1 0x10002ea0
	const char* ClassName() const override // vtable+0x0c
	{
		// STRING: LEGO1 0x100f0104
		return "IslePathActor";
	}

	// FUNCTION: LEGO1 0x10002eb0
	MxBool IsA(const char* p_name) const override // vtable+0x10
	{
		return !strcmp(p_name, IslePathActor::ClassName()) || LegoPathActor::IsA(p_name);
	}

	MxResult Create(MxDSAction& p_dsAction) override; // vtable+0x18
	void Destroy(MxBool p_fromDestructor) override;   // vtable+0x1c

	// FUNCTION: LEGO1 0x10002e70
	virtual MxLong HandleClick() { return 0; } // vtable+0xcc

	// FUNCTION: LEGO1 0x10002df0
	virtual MxLong HandleNotification0() { return 0; } // vtable+0xd0

	// FUNCTION: LEGO1 0x10002e80
	virtual MxLong HandleControl(LegoControlManagerNotificationParam&) { return 0; } // vtable+0xd4

	// FUNCTION: LEGO1 0x10002e90
	virtual MxLong HandleEndAnim(LegoEndAnimNotificationParam&) { return 0; } // vtable+0xd8

	// FUNCTION: LEGO1 0x10002e00
	virtual MxLong HandlePathStruct(LegoPathStructNotificationParam&) { return 0; } // vtable+0xdc

	virtual void Enter();                                                                        // vtable+0xe0
	virtual void Exit();                                                                         // vtable+0xe4
	virtual void SpawnPlayer(LegoGameState::Area p_area, MxBool p_enter, MxU8 p_flags);          // vtable+0xe8
	virtual void VTable0xec(MxMatrix p_transform, LegoPathBoundary* p_boundary, MxBool p_reset); // vtable+0xec

	// SYNTHETIC: LEGO1 0x10002ff0
	// IslePathActor::`scalar deleting destructor'

	void FUN_1001b660();

	void Reset()
	{
		m_roi->SetVisibility(TRUE);
		SetActorState(c_initial);
	}

	void SetWorld(LegoWorld* p_world) { m_world = p_world; }

	static void RegisterSpawnLocations();

protected:
	LegoWorld* m_world;             // 0x154
	LegoPathActor* m_previousActor; // 0x158
	MxFloat m_previousVel;          // 0x15c
};

#endif // ISLEPATHACTOR_H
