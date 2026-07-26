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
// VTABLE: BETA10 0x101b9090
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

	IslePathActor();

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

	virtual void Enter();                                                                         // vtable+0xe0
	virtual void Exit();                                                                          // vtable+0xe4
	virtual void SpawnPlayer(LegoGameState::Area p_area, MxBool p_enter, MxU8 p_flags);           // vtable+0xe8
	virtual void UpdateWorld(MxMatrix p_transform, LegoPathBoundary* p_boundary, MxBool p_reset); // vtable+0xec

	// FUNCTION: LEGO1 0x10002e10
	~IslePathActor() override { IslePathActor::Destroy(TRUE); }

	MxLong Notify(MxParam& p_param) override; // vtable+0x04

	// FUNCTION: LEGO1 0x10002ea0
	// FUNCTION: BETA10 0x10023fa0
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

	void TurnAround();

	void SetWorld(LegoWorld* p_world) { m_world = p_world; }

	static void RegisterSpawnLocations();

	// SYNTHETIC: LEGO1 0x10002ff0
	// IslePathActor::`scalar deleting destructor'

protected:
	LegoWorld* m_world;             // 0x154
	LegoPathActor* m_previousActor; // 0x158
	MxFloat m_previousVel;          // 0x15c
};

#endif // ISLEPATHACTOR_H
