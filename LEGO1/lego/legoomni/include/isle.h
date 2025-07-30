#ifndef ISLE_H
#define ISLE_H

#include "actionsfwd.h"
#include "legogamestate.h"
#include "legonamedplane.h"
#include "legostate.h"
#include "legoworld.h"
#include "radio.h"

class Ambulance;
class Bike;
class DuneBuggy;
class Helicopter;
class Jetski;
class JukeBoxEntity;
class LegoNamedTexture;
class Motocycle;
class LegoPathStructNotificationParam;
class Pizza;
class Pizzeria;
class RaceCar;
class SkateBoard;
class TowTrack;

// VTABLE: LEGO1 0x100d7028
// VTABLE: BETA10 0x101b9d40
// SIZE 0x26c
class Act1State : public LegoState {
public:
	enum ElevatorFloor {
		c_floor1 = 1,
		c_floor2,
		c_floor3
	};

	enum {
		e_none = 0,
		e_initial = 1,
		e_elevator = 2,
		e_pizza = 3,
		e_helicopter = 4,
		e_transitionToJetski = 5,
		e_transitionToRacecar = 6,
		e_transitionToTowtrack = 7,
		e_towtrack = 8,
		e_transitionToAmbulance = 9,
		e_ambulance = 10,
		e_jukebox = 11,
	};

	Act1State();

	// FUNCTION: LEGO1 0x100338a0
	// FUNCTION: BETA10 0x10036040
	const char* ClassName() const override // vtable+0x0c
	{
		// STRING: LEGO1 0x100f0154
		return "Act1State";
	}

	// FUNCTION: LEGO1 0x100338b0
	MxBool IsA(const char* p_name) const override // vtable+0x10
	{
		return !strcmp(p_name, Act1State::ClassName()) || LegoState::IsA(p_name);
	}

	MxBool Reset() override;                             // vtable+0x18
	MxResult Serialize(LegoStorage* p_storage) override; // vtable+0x1c

	void PlayCptClickDialogue();
	void StopCptClickDialogue();
	void RemoveActors();
	void PlaceActors();

	MxU32 GetState() { return m_state; }
	ElevatorFloor GetElevatorFloor() { return (ElevatorFloor) m_elevFloor; }
	MxU8 GetUnknown21() { return m_unk0x021; }

	void SetState(MxU32 p_state) { m_state = p_state; }
	void SetElevatorFloor(ElevatorFloor p_elevFloor) { m_elevFloor = p_elevFloor; }
	void SetUnknown21(MxU8 p_unk0x21) { m_unk0x021 = p_unk0x21; }

	// SYNTHETIC: LEGO1 0x10033960
	// Act1State::`scalar deleting destructor'

	// TODO: Most likely getters/setters are not used according to BETA.

	Playlist m_cptClickDialogue;                  // 0x008
	IsleScript::Script m_currentCptClickDialogue; // 0x014
	MxU32 m_state;                                // 0x018
	MxS16 m_elevFloor;                            // 0x01c
	MxBool m_unk0x01e;                            // 0x01e
	MxBool m_unk0x01f;                            // 0x01f
	MxBool m_planeActive;                         // 0x020
	undefined m_unk0x021;                         // 0x021
	MxBool m_unk0x022;                            // 0x022
	undefined m_unk0x023;                         // 0x023
	LegoNamedPlane m_motocyclePlane;              // 0x024
	LegoNamedPlane m_bikePlane;                   // 0x070
	LegoNamedPlane m_skateboardPlane;             // 0x0bc
	LegoNamedPlane m_helicopterPlane;             // 0x108
	LegoNamedTexture* m_helicopterWindshield;     // 0x154
	LegoNamedTexture* m_helicopterJetLeft;        // 0x158
	LegoNamedTexture* m_helicopterJetRight;       // 0x15c
	Helicopter* m_helicopter;                     // 0x160
	LegoNamedPlane m_jetskiPlane;                 // 0x164
	LegoNamedTexture* m_jetskiFront;              // 0x1b0
	LegoNamedTexture* m_jetskiWindshield;         // 0x1b4
	Jetski* m_jetski;                             // 0x1b8
	LegoNamedPlane m_dunebuggyPlane;              // 0x1bc
	LegoNamedTexture* m_dunebuggyFront;           // 0x208
	DuneBuggy* m_dunebuggy;                       // 0x20c
	LegoNamedPlane m_racecarPlane;                // 0x210
	LegoNamedTexture* m_racecarFront;             // 0x25c
	LegoNamedTexture* m_racecarBack;              // 0x260
	LegoNamedTexture* m_racecarTail;              // 0x264
	RaceCar* m_racecar;                           // 0x268
};

// VTABLE: LEGO1 0x100d6fb8
// VTABLE: BETA10 0x101b9cc8
// SIZE 0x140
class Isle : public LegoWorld {
public:
	enum {
		c_playCamAnims = 0x20,
		c_playMusic = 0x40
	};

	Isle();
	~Isle() override;

	MxLong Notify(MxParam& p_param) override; // vtable+0x04

	// FUNCTION: LEGO1 0x10030900
	MxBool VTable0x5c() override { return TRUE; } // vtable+0x5c

	// FUNCTION: LEGO1 0x10030910
	// FUNCTION: BETA10 0x10035d70
	const char* ClassName() const override // vtable+0x0c
	{
		// STRING: LEGO1 0x100f0458
		return "Isle";
	}

	// FUNCTION: LEGO1 0x10030920
	MxBool IsA(const char* p_name) const override // vtable+0x10
	{
		return !strcmp(p_name, Isle::ClassName()) || LegoWorld::IsA(p_name);
	}

	MxResult Create(MxDSAction& p_dsAction) override;   // vtable+0x18
	void ReadyWorld() override;                         // vtable+0x50
	void Add(MxCore* p_object) override;                // vtable+0x58
	void VTable0x60() override;                         // vtable+0x60
	MxBool Escape() override;                           // vtable+0x64
	void Enable(MxBool p_enable) override;              // vtable+0x68
	virtual void RemoveVehicle(LegoPathActor* p_actor); // vtable+0x6c

	void SetDestLocation(LegoGameState::Area p_destLocation) { m_destLocation = p_destLocation; }
	MxBool HasHelicopter() { return m_helicopter != NULL; }

	void SwitchToInfocenter();

	friend class Act1State;

	// SYNTHETIC: LEGO1 0x10030a30
	// Isle::`scalar deleting destructor'

protected:
	MxLong HandleEndAction(MxEndActionNotificationParam& p_param);
	MxLong HandleControl(LegoControlManagerNotificationParam& p_param);
	MxLong HandlePathStruct(LegoPathStructNotificationParam& p_param);
	MxLong HandleTransitionEnd();
	void HandleElevatorEndAction();
	void UpdateGlobe();
	void CheckAreaExiting();
	void CreateState();
	void TransitionToOverlay(
		IsleScript::Script p_script,
		JukeboxScript::Script p_music,
		const char* p_cameraLocation,
		MxBool p_setCamera
	);

	Act1State* m_act1state;             // 0xf8
	Pizza* m_pizza;                     // 0xfc
	Pizzeria* m_pizzeria;               // 0x100
	TowTrack* m_towtrack;               // 0x104
	Ambulance* m_ambulance;             // 0x108
	JukeBoxEntity* m_jukebox;           // 0x10c
	Helicopter* m_helicopter;           // 0x110
	Bike* m_bike;                       // 0x114
	DuneBuggy* m_dunebuggy;             // 0x118
	Motocycle* m_motocycle;             // 0x11c
	SkateBoard* m_skateboard;           // 0x120
	RaceCar* m_racecar;                 // 0x124
	Jetski* m_jetski;                   // 0x128
	Radio m_radio;                      // 0x12c
	LegoGameState::Area m_destLocation; // 0x13c
};

#endif // ISLE_H
