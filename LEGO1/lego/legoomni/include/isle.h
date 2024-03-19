#ifndef ISLE_H
#define ISLE_H

#include "legogamestate.h"
#include "legoworld.h"
#include "radio.h"

class Pizza;
class Pizzeria;
class TowTrack;
class Ambulance;
class JukeBoxEntity;
class Helicopter;
class Bike;
class DuneBuggy;
class Motocycle;
class SkateBoard;
class RaceCar;
class Jetski;
class Act1State;

namespace IsleScript
{
#ifdef COMPAT_MODE
enum Script : int;
#else
enum Script;
#endif
} // namespace IsleScript

namespace JukeboxScript
{
#ifdef COMPAT_MODE
enum Script : int;
#else
enum Script;
#endif
} // namespace JukeboxScript

// VTABLE: LEGO1 0x100d6fb8
// SIZE 0x140
class Isle : public LegoWorld {
public:
	// For g_unk0x100f1198
	enum {
		c_bit7 = 0x40
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

	MxBool VTable0x64() override;                    // vtable+64
	void Enable(MxBool p_enable) override;           // vtable+68
	virtual void VTable0x6c(IslePathActor* p_actor); // vtable+6c

	MxLong HandleEndAction(MxEndActionNotificationParam& p_param);
	MxLong HandleClick(LegoControlManagerEvent& p_param);
	MxLong HandleType19Notification(MxParam& p_param);
	MxLong HandleTransitionEnd();
	void HandleElevatorEndAction();
	void FUN_10031590();
	void FUN_10032620();
	void FUN_100330e0();
	void FUN_10032d30(
		IsleScript::Script p_script,
		JukeboxScript::Script p_music,
		const char* p_cameraLocation,
		MxBool p_und
	);

	inline void SetDestLocation(LegoGameState::Area p_destLocation) { m_destLocation = p_destLocation; }

	// SYNTHETIC: LEGO1 0x10030a30
	// Isle::`scalar deleting destructor'

protected:
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
