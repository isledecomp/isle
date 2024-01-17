#ifndef HELICOPTER_H
#define HELICOPTER_H

#include "helicopterstate.h"
#include "islepathactor.h"
#include "realtime/matrix.h"

// SIZE 0x34
class HelicopterSubclass {
public:
	inline HelicopterSubclass() : m_unk0x30(0) {}
	MxResult FUN_100040a0(Vector4& p_v, float p_f);

private:
	Mx4DPointFloat m_unk0x0;  // 0x0
	Mx4DPointFloat m_unk0x18; // 0x18
	undefined4 m_unk0x30;     // 0x30
};

// VTABLE: LEGO1 0x100d40f8
// SIZE 0x230
class Helicopter : public IslePathActor {
public:
	Helicopter();
	virtual ~Helicopter() override; // vtable+0x0

	// FUNCTION: LEGO1 0x10003070
	inline virtual const char* ClassName() const override // vtable+0x0c
	{
		// STRING: LEGO1 0x100f0130
		return "Helicopter";
	}

	// FUNCTION: LEGO1 0x10003080
	inline virtual MxBool IsA(const char* p_name) const override // vtable+0x10
	{
		return !strcmp(p_name, Helicopter::ClassName()) || IslePathActor::IsA(p_name);
	}

	virtual MxResult Create(MxDSAction& p_dsAction) override;              // vtable+0x18
	void VTable0x70(float p_float) override;                               // vtable+0x70
	void VTable0x74(Matrix4& p_transform) override;                        // vtable+0x74
	virtual MxU32 VTable0xcc() override;                                   // vtable+0xcc
	virtual MxU32 VTable0xd4(MxType17NotificationParam& p_param) override; // vtable+0xd4
	virtual MxU32 VTable0xd8(MxType18NotificationParam& p_param) override; // vtable+0xd8
	virtual void VTable0xe4() override;                                    // vtable+0xe4

	// SYNTHETIC: LEGO1 0x10003210
	// Helicopter::`scalar deleting destructor'

protected:
	MxMatrix m_unk0x160;           // 0x160
	MxMatrix m_unk0x1a8;           // 0x1a8
	float m_unk0x1f0;              // 0x1f0
	HelicopterSubclass m_unk0x1f4; // 0x1f4
	HelicopterState* m_state;      // 0x228
	MxAtomId m_script;             // 0x22c

private:
	void GetState();
};

#endif // HELICOPTER_H
