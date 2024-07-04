#ifndef LEGORACECAR_H
#define LEGORACECAR_H

#include "legocarraceactor.h"
#include "legoracemap.h"

// SIZE 0x08
struct EdgeReference {
	const char* m_name;       // 0x00
	LegoPathBoundary* m_data; // 0x04
};

// VTABLE: LEGO1 0x100d58a0 LegoRaceActor
// VTABLE: LEGO1 0x100d58a8 LegoAnimActor
// VTABLE: LEGO1 0x100d58b8 LegoPathActor
// VTABLE: LEGO1 0x100d5984 LegoRaceMap
// VTABLE: LEGO1 0x100d5988 LegoCarRaceActor
// SIZE 0x200
class LegoRaceCar : public LegoCarRaceActor, public LegoRaceMap {
public:
	LegoRaceCar();
	~LegoRaceCar() override;

	MxLong Notify(MxParam& p_param) override; // vtable+0x04

	// FUNCTION: LEGO1 0x100142a0
	const char* ClassName() const override // vtable+0x0c
	{
		// STRING: LEGO1 0x100f0548
		return "LegoRaceCar";
	}

	// FUNCTION: LEGO1 0x100142c0
	MxBool IsA(const char* p_name) const override // vtable+0x10
	{
		return !strcmp(p_name, LegoRaceCar::ClassName()) || LegoCarRaceActor::IsA(p_name);
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
	) override;                                                          // vtable+0x6c
	void VTable0x70(float p_float) override;                             // vtable+0x70
	MxResult VTable0x94(LegoPathActor* p_actor, MxBool p_bool) override; // vtable+0x94
	void SwitchBoundary(LegoPathBoundary*& p_boundary, LegoUnknown100db7f4*& p_edge, float& p_unk0xe4)
		override;                   // vtable+0x98
	MxResult VTable0x9c() override; // vtable+0x9c

	virtual void SetMaxLinearVelocity(float p_maxLinearVelocity);
	virtual void FUN_10012ff0(float);
	virtual MxBool FUN_10013130(float);

	// SYNTHETIC: LEGO1 0x10014240
	// LegoRaceCar::`scalar deleting destructor'

private:
	undefined m_unk0x54;            // 0x54
	undefined4 m_unk0x58;           // 0x58
	Mx3DPointFloat m_unk0x5c;       // 0x5c
	LegoAnimActorStruct* m_unk0x70; // 0x70
	LegoAnimActorStruct* m_unk0x74; // 0x74
	LegoPathBoundary* m_unk0x78;    // 0x78
	LegoPathBoundary* m_unk0x7c;    // 0x7c

	static EdgeReference g_edgeReferences[];
	static const EdgeReference* g_pEdgeReferences;
};

#endif // LEGORACECAR_H
