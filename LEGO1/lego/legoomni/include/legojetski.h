#ifndef LEGOJETSKI_H
#define LEGOJETSKI_H

#include "legojetskiraceactor.h"
#include "legoracemap.h"

// VTABLE: LEGO1 0x100d5a08 LegoCarRaceActor
// VTABLE: LEGO1 0x100d5a28 LegoRaceActor
// VTABLE: LEGO1 0x100d5a30 LegoAnimActor
// VTABLE: LEGO1 0x100d5a40 LegoPathActor
// VTABLE: LEGO1 0x100d5b10 LegoRaceMap
// SIZE 0x1dc
class LegoJetski : public LegoJetskiRaceActor, public LegoRaceMap {
public:
	LegoJetski();
	~LegoJetski() override;

	MxLong Notify(MxParam& p_param) override; // vtable+0x04

	// FUNCTION: LEGO1 0x10013e90
	const char* ClassName() const override // vtable+0x0c
	{
		// STRING: LEGO1 0x100f053c
		return "LegoJetski";
	}

	// FUNCTION: LEGO1 0x10013eb0
	MxBool IsA(const char* p_name) const override // vtable+0x10
	{
		return !strcmp(p_name, LegoJetski::ClassName()) || LegoJetskiRaceActor::IsA(p_name);
	}

	void ParseAction(char*) override;                  // vtable+0x20
	void SetWorldSpeed(MxFloat p_worldSpeed) override; // vtable+0x30
	MxU32 VTable0x6c(
		LegoPathBoundary* p_boundary,
		Vector3& p_v1,
		Vector3& p_v2,
		float p_f1,
		float p_f2,
		Vector3& p_v3
	) override;                                                        // vtable+0x6c
	void VTable0x70(float p_time) override;                            // vtable+0x70
	MxResult HitActor(LegoPathActor* p_actor, MxBool p_bool) override; // vtable+0x94
	void SwitchBoundary(LegoPathBoundary*& p_boundary, LegoUnknown100db7f4*& p_edge, float& p_unk0xe4)
		override;                   // vtable+0x98
	MxResult VTable0x9c() override; // vtable+0x9c

	virtual void FUN_100136f0(float p_worldSpeed);

	// SYNTHETIC: LEGO1 0x10013e30
	// LegoJetski::`scalar deleting destructor'
};

// GLOBAL: LEGO1 0x100d59b8
// LegoJetski::`vbtable'{for `LegoCarRaceActor'}

// GLOBAL: LEGO1 0x100d59c8
// LegoJetski::`vbtable'{for `LegoRaceActor'}

// GLOBAL: LEGO1 0x100d59d8
// LegoJetski::`vbtable'{for `LegoAnimActor'}

// GLOBAL: LEGO1 0x100d59e0
// LegoJetski::`vbtable'

// GLOBAL: LEGO1 0x100d59f0
// LegoJetski::`vbtable'{for `LegoJetskiRaceActor'}

#endif // LEGOJETSKI_H
