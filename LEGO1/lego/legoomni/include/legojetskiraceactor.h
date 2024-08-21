#ifndef LEGOJETSKIRACEACTOR_H
#define LEGOJETSKIRACEACTOR_H

#include "legoracespecial.h"

// VTABLE: LEGO1 0x100da208 LegoCarRaceActor
// VTABLE: LEGO1 0x100da228 LegoRaceActor
// VTABLE: LEGO1 0x100da230 LegoAnimActor
// VTABLE: LEGO1 0x100da240 LegoPathActor
// SIZE 0x1a8
class LegoJetskiRaceActor : public virtual LegoCarRaceActor {
public:
	LegoJetskiRaceActor();

	// FUNCTION: LEGO1 0x10081d90
	const char* ClassName() const override // vtable+0x0c
	{
		// STRING: LEGO1 0x100f0554
		return "LegoJetskiRaceActor";
	}

	// FUNCTION: LEGO1 0x10081db0
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
	void VTable0x70(float p_float) override;                                   // vtable+0x70
	MxS32 VTable0x1c(LegoPathBoundary* p_boundary, LegoEdge* p_edge) override; // vtable+0x1c

	// SYNTHETIC: LEGO1 0x10013a80
	// LegoJetskiRaceActor::`vbase destructor'

	// SYNTHETIC: LEGO1 0x10081d50
	// LegoJetskiRaceActor::`scalar deleting destructor'

	// SYNTHETIC: LEGO1 0x10013ba0
	// LegoJetskiRaceActor::~LegoJetskiRaceActor
};

#endif // LEGOJETSKIRACEACTOR_H
