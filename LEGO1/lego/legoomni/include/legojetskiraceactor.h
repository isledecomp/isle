#ifndef LEGOJETSKIRACEACTOR_H
#define LEGOJETSKIRACEACTOR_H

#include "legoracespecial.h"

// VTABLE: LEGO1 0x100da208 LegoCarRaceActor
// VTABLE: LEGO1 0x100da228 LegoRaceActor
// VTABLE: LEGO1 0x100da230 LegoAnimActor
// VTABLE: LEGO1 0x100da240 LegoPathActor
// VTABLE: BETA10 0x101bd348 LegoCarRaceActor
// VTABLE: BETA10 0x101bd370 LegoRaceActor
// VTABLE: BETA10 0x101bd378 LegoAnimActor
// VTABLE: BETA10 0x101bd390 LegoPathActor
// SIZE 0x1a8
class LegoJetskiRaceActor : public virtual LegoCarRaceActor {
public:
	LegoJetskiRaceActor();

	// FUNCTION: LEGO1 0x10081d90
	// FUNCTION: BETA10 0x100aa920
	const char* ClassName() const override // vtable+0x0c
	{
		// STRING: LEGO1 0x100f0554
		return "LegoJetskiRaceActor";
	}

	// FUNCTION: LEGO1 0x10081db0
	// FUNCTION: BETA10 0x100aa960
	MxBool IsA(const char* p_name) const override // vtable+0x10
	{
		return !strcmp(p_name, LegoJetskiRaceActor::ClassName()) || LegoCarRaceActor::IsA(p_name);
	}

	MxU32 VTable0x6c(
		LegoPathBoundary* p_boundary,
		Vector3& p_v1,
		Vector3& p_v2,
		float p_f1,
		float p_f2,
		Vector3& p_v3
	) override;                                                                // vtable+0x6c
	void Animate(float p_time) override;                                       // vtable+0x70
	MxS32 VTable0x1c(LegoPathBoundary* p_boundary, LegoEdge* p_edge) override; // vtable+0x1c

	// SYNTHETIC: LEGO1 0x10013a80
	// LegoJetskiRaceActor::`vbase destructor'

	// SYNTHETIC: LEGO1 0x10081d50
	// LegoJetskiRaceActor::`scalar deleting destructor'

	// SYNTHETIC: LEGO1 0x10013ba0
	// LegoJetskiRaceActor::~LegoJetskiRaceActor
};

// GLOBAL: LEGO1 0x100da1f0
// LegoJetskiRaceActor::`vbtable'{for `LegoJetskiRaceActor'}

// GLOBAL: LEGO1 0x100da1e8
// LegoJetskiRaceActor::`vbtable'{for `LegoAnimActor'}

// GLOBAL: LEGO1 0x100da1d8
// LegoJetskiRaceActor::`vbtable'{for `LegoRaceActor'}

// GLOBAL: LEGO1 0x100da1c8
// LegoJetskiRaceActor::`vbtable'{for `LegoCarRaceActor'}

#endif // LEGOJETSKIRACEACTOR_H
