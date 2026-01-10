#ifndef DOORS_H
#define DOORS_H

#include "legopathactor.h"

class LegoROI;

// VTABLE: LEGO1 0x100d4788
// VTABLE: BETA10 0x101bcfb8
// SIZE 0x1f8
class Doors : public LegoPathActor {
public:
	Doors() : m_state(0), m_ltDoor(NULL), m_rtDoor(NULL), m_angle(0) {}

	// FUNCTION: LEGO1 0x1000e430
	// FUNCTION: BETA10 0x100a7f20
	const char* ClassName() const override // vtable+0x0c
	{
		// STRING: LEGO1 0x100f03e8
		return "Doors";
	}

	// FUNCTION: LEGO1 0x1000e440
	MxBool IsA(const char* p_name) const override // vtable+0x10
	{
		return !strcmp(p_name, Doors::ClassName()) || LegoPathActor::IsA(p_name);
	}

	void ParseAction(char* p_extra) override;                          // vtable+0x20
	void Animate(float p_time) override;                               // vtable+0x70
	MxResult HitActor(LegoPathActor* p_actor, MxBool p_bool) override; // vtable+0x94
	virtual MxFloat CalculateAngle(float p_time);                      // vtable+0xcc

	// SYNTHETIC: LEGO1 0x1000e580
	// Doors::`scalar deleting destructor'

private:
	enum {
		e_none = 0,
		e_closed = 1,
		e_cycling = 2,
	};

	undefined4 m_state;             // 0x154
	MxFloat m_hitTime;              // 0x158
	LegoROI* m_ltDoor;              // 0x15c
	LegoROI* m_rtDoor;              // 0x160
	MxMatrix m_ltDoorOriginalLocal; // 0x164
	MxMatrix m_rtDoorOriginalLocal; // 0x1ac
	MxFloat m_angle;                // 0x1f4
};

#endif // DOORS_H
