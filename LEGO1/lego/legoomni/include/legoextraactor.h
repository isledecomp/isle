#ifndef LEGOEXTRAACTOR_H
#define LEGOEXTRAACTOR_H

#include "legoanimactor.h"

// VTABLE: LEGO1 0x100d6c00 LegoAnimActor
// VTABLE: LEGO1 0x100d6c10 LegoPathActor
// VTABLE: LEGO1 0x100d6cdc LegoExtraActor
// SIZE 0x1dc
class LegoExtraActor : public virtual LegoAnimActor {
public:
	enum Axis {
		e_posz,
		e_negz,
		e_posx,
		e_negx
	};

	LegoExtraActor();
	~LegoExtraActor() override;

	// FUNCTION: LEGO1 0x1002b7b0
	inline const char* ClassName() const override // vtable+0x0c
	{
		// STRING: LEGO1 0x100f3204
		return "LegoExtraActor";
	}

	// FUNCTION: LEGO1 0x1002b7d0
	inline MxBool IsA(const char* p_name) const override // vtable+0x10
	{
		return !strcmp(p_name, LegoExtraActor::ClassName()) || LegoAnimActor::IsA(p_name);
	}

	void SetWorldSpeed(MxFloat p_worldSpeed) override; // vtable+0x30
	void VTable0x68(Mx3DPointFloat& p_point1, Mx3DPointFloat& p_point2, Mx3DPointFloat& p_point3)
		override;                                                // vtable+0x68
	void VTable0x6c() override;                                  // vtable+0x6c
	void VTable0x70(float) override;                             // vtable+0x70
	void VTable0x74(Matrix4& p_transform) override;              // vtable+0x74
	MxU32 VTable0x90(float p_float, Matrix4& p_matrix) override; // vtable+0x90
	MxS32 VTable0x94() override;                                 // vtable+0x94
	void VTable0x9c() override;                                  // vtable+0x9c
	void VTable0xa4() override;                                  // vtable+0xa4
	void VTable0xc4() override;                                  // vtable+0xc4

	virtual MxResult FUN_1002aae0();

	// SYNTHETIC: LEGO1 0x1002b760
	// LegoExtraActor::`scalar deleting destructor'

private:
	MxFloat m_scheduledTime;        // 0x08
	undefined m_unk0x0c;            // 0x0c
	MxU8 m_axis;                    // 0x0d
	undefined m_unk0x0e;            // 0x0e
	undefined4 m_unk0x10;           // 0x10
	MxU8 m_unk0x14;                 // 0x14
	MxU8 m_unk0x15;                 // 0x15
	MxMatrix m_unk0x18;             // 0x18
	LegoAnimActorStruct* m_unk0x60; // 0x60
	LegoAnimActorStruct* m_unk0x64; // 0x64
};

// GLOBAL: LEGO1 0x100d6be8
// LegoExtraActor::`vbtable'{for `LegoAnimActor'}

// GLOBAL: LEGO1 0x100d6bf0
// LegoExtraActor::`vbtable'{for `LegoExtraActor'}

#endif // LEGOEXTRAACTOR_H
