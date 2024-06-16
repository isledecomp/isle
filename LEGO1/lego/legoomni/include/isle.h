#ifndef ISLE_H
#define ISLE_H

#include "actionsfwd.h"
#include "legogamestate.h"
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
// SIZE 0x26c
class Act1State : public LegoState {
public:
	enum ElevatorFloor {
		c_floor1 = 1,
		c_floor2,
		c_floor3
	};

	enum {
		e_unk953 = 953,
		e_unk954 = 954,
		e_unk955 = 955,
	};

	// SIZE 0x4c
	class NamedPlane {
	public:
		// FUNCTION: LEGO1 0x10033800
		NamedPlane() {}

		inline void SetName(const char* p_name) { m_name = p_name; }
		inline const MxString* GetName() const { return &m_name; }

		// FUNCTION: LEGO1 0x100344d0
		MxResult Serialize(LegoFile* p_file)
		{
			if (p_file->IsWriteMode()) {
				p_file->WriteString(m_name);
				p_file->WriteVector3(m_point1);
				p_file->WriteVector3(m_point2);
				p_file->WriteVector3(m_point3);
			}
			else if (p_file->IsReadMode()) {
				p_file->ReadString(m_name);
				p_file->ReadVector3(m_point1);
				p_file->ReadVector3(m_point2);
				p_file->ReadVector3(m_point3);
			}

			return SUCCESS;
		}

	private:
		MxString m_name;         // 0x00
		Mx3DPointFloat m_point1; // 0x10
		Mx3DPointFloat m_point2; // 0x24
		Mx3DPointFloat m_point3; // 0x38
	};

	Act1State();

	// FUNCTION: LEGO1 0x100338a0
	inline const char* ClassName() const override // vtable+0x0c
	{
		// STRING: LEGO1 0x100f0154
		return "Act1State";
	}

	// FUNCTION: LEGO1 0x100338b0
	inline MxBool IsA(const char* p_name) const override // vtable+0x10
	{
		return !strcmp(p_name, Act1State::ClassName()) || LegoState::IsA(p_name);
	}

	MxBool SetFlag() override;                     // vtable+0x18
	MxResult Serialize(LegoFile* p_file) override; // vtable+0x1c

	void FUN_10034660();
	void FUN_100346a0();
	void FUN_10034b60();
	void FUN_10034d00();

	inline MxU32 GetUnknown18() { return m_unk0x018; }
	inline ElevatorFloor GetElevatorFloor() { return (ElevatorFloor) m_elevFloor; }
	inline MxU8 GetUnknown21() { return m_unk0x021; }

	inline void SetUnknown18(MxU32 p_unk0x18) { m_unk0x018 = p_unk0x18; }
	inline void SetElevatorFloor(ElevatorFloor p_elevFloor) { m_elevFloor = p_elevFloor; }
	inline void SetUnknown21(MxU8 p_unk0x21) { m_unk0x021 = p_unk0x21; }

	// SYNTHETIC: LEGO1 0x10033960
	// Act1State::`scalar deleting destructor'

	// TODO: Most likely getters/setters are not used according to BETA.

	MxS32* m_unk0x008;            // 0x008 FIXME: count for m_unk0x008
	MxS16 m_unk0x00c;             // 0x00c
	undefined2 m_unk0x00e;        // 0x00e
	undefined2 m_unk0x010;        // 0x010
	undefined m_unk0x012;         // 0x012
	MxS32 m_unk0x014;             // 0x014
	MxU32 m_unk0x018;             // 0x018
	MxS16 m_elevFloor;            // 0x01c
	MxBool m_unk0x01e;            // 0x01e
	MxBool m_unk0x01f;            // 0x01f
	MxBool m_planeActive;         // 0x020
	undefined m_unk0x021;         // 0x021
	MxBool m_unk0x022;            // 0x022
	undefined m_unk0x023;         // 0x023
	NamedPlane m_unk0x024;        // 0x024
	NamedPlane m_unk0x070;        // 0x070
	NamedPlane m_unk0x0bc;        // 0x0bc
	NamedPlane m_unk0x108;        // 0x108
	LegoNamedTexture* m_unk0x154; // 0x154
	LegoNamedTexture* m_unk0x158; // 0x158
	LegoNamedTexture* m_unk0x15c; // 0x15c
	MxCore* m_unk0x160;           // 0x160
	NamedPlane m_unk0x164;        // 0x164
	LegoNamedTexture* m_unk0x1b0; // 0x1b0
	LegoNamedTexture* m_unk0x1b4; // 0x1b4
	MxCore* m_unk0x1b8;           // 0x1b8
	NamedPlane m_unk0x1bc;        // 0x1bc
	LegoNamedTexture* m_unk0x208; // 0x208
	MxCore* m_unk0x20c;           // 0x20c
	NamedPlane m_unk0x210;        // 0x210
	LegoNamedTexture* m_unk0x25c; // 0x25c
	LegoNamedTexture* m_unk0x260; // 0x260
	LegoNamedTexture* m_unk0x264; // 0x264
	MxCore* m_unk0x268;           // 0x268
};

// FUNCTION: LEGO1 0x10033a70
// Act1State::NamedPlane::~NamedPlane

// VTABLE: LEGO1 0x100d6fb8
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

	// FUNCTION: LEGO1 0x10030910
	inline const char* ClassName() const override // vtable+0x0c
	{
		// STRING: LEGO1 0x100f0458
		return "Isle";
	}

	// FUNCTION: LEGO1 0x10030920
	inline MxBool IsA(const char* p_name) const override // vtable+0x10
	{
		return !strcmp(p_name, Isle::ClassName()) || LegoWorld::IsA(p_name);
	}

	MxResult Create(MxDSAction& p_dsAction) override; // vtable+0x18
	void ReadyWorld() override;                       // vtable+50
	void Add(MxCore* p_object) override;              // vtable+58

	// FUNCTION: LEGO1 0x10030900
	MxBool VTable0x5c() override { return TRUE; } // vtable+5c

	// FUNCTION: LEGO1 0x10033170
	void VTable0x60() override {} // vtable+60

	MxBool Escape() override;                        // vtable+64
	void Enable(MxBool p_enable) override;           // vtable+68
	virtual void VTable0x6c(LegoPathActor* p_actor); // vtable+6c

	inline void SetDestLocation(LegoGameState::Area p_destLocation) { m_destLocation = p_destLocation; }

	void FUN_10033350();

	// SYNTHETIC: LEGO1 0x10030a30
	// Isle::`scalar deleting destructor'

protected:
	MxLong HandleEndAction(MxEndActionNotificationParam& p_param);
	MxLong HandleControl(LegoControlManagerNotificationParam& p_param);
	MxLong HandlePathStruct(LegoPathStructNotificationParam& p_param);
	MxLong HandleTransitionEnd();
	void HandleElevatorEndAction();
	void UpdateGlobe();
	void FUN_10032620();
	void CreateState();
	void FUN_10032d30(
		IsleScript::Script p_script,
		JukeboxScript::Script p_music,
		const char* p_cameraLocation,
		MxBool p_und
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
