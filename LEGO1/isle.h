#ifndef ISLE_H
#define ISLE_H

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
class Motorcycle;
class SkateBoard;
class RaceCar;
class Jetski;
class Act1State;

// VTABLE: LEGO1 0x100d6fb8
// SIZE 0x140
// Radio at 0x12c
class Isle : public LegoWorld {
public:
	Isle();
	virtual ~Isle() override;

	// FUNCTION: LEGO1 0x10030910
	inline virtual const char* ClassName() const override // vtable+0x0c
	{
		// GLOBAL: LEGO1 0x100f0458
		return "Isle";
	}

	// FUNCTION: LEGO1 0x10030920
	inline virtual MxBool IsA(const char* p_name) const override // vtable+0x10
	{
		return !strcmp(p_name, Isle::ClassName()) || LegoWorld::IsA(p_name);
	}
	virtual MxResult Create(MxDSObject& p_dsObject) override; // vtable+0x18
	virtual void Stop() override;                             // vtable+50
	virtual void VTable0x58(MxCore* p_object);                // vtable+58
	// FUNCTION: LEGO1 0x10030900
	virtual MxBool VTable0x5c() { return TRUE; } // vtable+5c
	// FUNCTION: LEGO1 0x10033170
	virtual void VTable0x60() {}           // vtable+60
	virtual MxBool VTable0x64();           // vtable+64
	virtual void VTable0x68(MxBool p_add); // vtable+68
	virtual void VTable0x6c(MxCore* p_object);

	inline void SetUnknown13c(MxU32 p_unk0x13c) { m_unk0x13c = p_unk0x13c; }

protected:
	Act1State* m_act1state;   // 0xf8
	Pizza* m_pizza;           // 0xfc
	Pizzeria* m_pizzeria;     // 0x100
	TowTrack* m_towtrack;     // 0x104
	Ambulance* m_ambulance;   // 0x108
	JukeBoxEntity* m_jukebox; // 0x10c
	Helicopter* m_helicopter; // 0x110
	Bike* m_bike;             // 0x114
	DuneBuggy* m_dunebuggy;   // 0x118
	Motorcycle* m_motorcycle; // 0x11c
	SkateBoard* m_skateboard; // 0x120
	RaceCar* m_racecar;       // 0x124
	Jetski* m_jetski;         // 0x128
	Radio m_radio;            // 0x12c
	MxU32 m_unk0x13c;         // 0x13c
};

#endif // ISLE_H
