#ifndef LEGOCARRACEACTOR_H
#define LEGOCARRACEACTOR_H

#include "legoraceactor.h"

extern const char* g_raceState;
extern const char* g_fuel;
extern const char* g_racing;

// VTABLE: LEGO1 0x100da0c0 LegoRaceActor
// VTABLE: LEGO1 0x100da0c8 LegoAnimActor
// VTABLE: LEGO1 0x100da0d8 LegoPathActor
// VTABLE: LEGO1 0x100da1a8 LegoCarRaceActor
// VTABLE: BETA10 0x101bea74 LegoRaceActor
// VTABLE: BETA10 0x101bea78 LegoAnimActor
// VTABLE: BETA10 0x101bea90 LegoPathActor
// VTABLE: BETA10 0x101beb80 LegoCarRaceActor
// SIZE 0x1a0
class LegoCarRaceActor : public virtual LegoRaceActor {
public:
	LegoCarRaceActor();

	// FUNCTION: LEGO1 0x10081660
	// FUNCTION: BETA10 0x100aab10
	const char* ClassName() const override // vtable+0x0c
	{
		// STRING: LEGO1 0x100f0568
		return "LegoCarRaceActor";
	}

	// FUNCTION: LEGO1 0x10081680
	// FUNCTION: BETA10 0x100aa9e0
	MxBool IsA(const char* p_name) const override // vtable+0x10
	{
		return !strcmp(p_name, LegoCarRaceActor::ClassName()) || LegoRaceActor::IsA(p_name);
	}

	MxU32 VTable0x6c(
		LegoPathBoundary* p_boundary,
		Vector3& p_v1,
		Vector3& p_v2,
		float p_f1,
		float p_f2,
		Vector3& p_v3
	) override;                          // vtable+0x6c
	void Animate(float p_time) override; // vtable+0x70
	void SwitchBoundary(LegoPathBoundary*& p_boundary, LegoUnknown100db7f4*& p_edge, float& p_unk0xe4)
		override;                   // vtable+0x98
	MxResult VTable0x9c() override; // vtable+0x9c

	// LegoCarRaceActor vtable

	virtual void FUN_10080590(float p_time); // vtable+0x00

	// FUNCTION: LEGO1 0x10012bb0
	virtual void FUN_10012bb0(float p_unk0x14) { m_unk0x14 = p_unk0x14; } // vtable+0x04

	// FUNCTION: LEGO1 0x10012bc0
	virtual float FUN_10012bc0() { return m_unk0x14; } // vtable+0x08

	// FUNCTION: LEGO1 0x10012bd0
	virtual void FUN_10012bd0(float p_unk0x10) { m_unk0x10 = p_unk0x10; } // vtable+0x0c

	// FUNCTION: LEGO1 0x10012be0
	virtual float FUN_10012be0() { return m_unk0x10; } // vtable+0x10

	// FUNCTION: LEGO1 0x10012bf0
	virtual void FUN_10012bf0(float p_unk0x18) { m_unk0x18 = p_unk0x18; } // vtable+0x14

	// FUNCTION: LEGO1 0x10012c00
	virtual float FUN_10012c00() { return m_unk0x18; } // vtable+0x18

	virtual MxS32 VTable0x1c(LegoPathBoundary* p_boundary, LegoEdge* p_edge); // vtable+0x1c

	// SYNTHETIC: LEGO1 0x10012c30
	// LegoCarRaceActor::`vbase destructor'

	// SYNTHETIC: LEGO1 0x10081620
	// LegoCarRaceActor::`scalar deleting destructor'

	// SYNTHETIC: LEGO1 0x10012d80
	// LegoCarRaceActor::~LegoCarRaceActor

protected:
	MxFloat m_unk0x08; // 0x08
	MxU8 m_unk0x0c;    // 0x0c

	// Could be a multiplier for the maximum speed when going straight
	MxFloat m_unk0x10; // 0x10

	// Could be the acceleration
	MxFloat m_unk0x14; // 0x14

	MxFloat m_unk0x18; // 0x18

	// Could be the current timestamp for time-based movement
	MxFloat m_unk0x1c; // 0x1c

	static MxFloat g_unk0x100f7aec;
};

// GLOBAL: LEGO1 0x100da0b0
// LegoCarRaceActor::`vbtable'

// GLOBAL: LEGO1 0x100da0a8
// LegoCarRaceActor::`vbtable'{for `LegoAnimActor'}

// GLOBAL: LEGO1 0x100da098
// LegoCarRaceActor::`vbtable'{for `LegoRaceActor'}

#endif // LEGOCARRACEACTOR_H
