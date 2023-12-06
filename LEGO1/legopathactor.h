#ifndef LEGOPATHACTOR_H
#define LEGOPATHACTOR_H

#include "legoactor.h"
#include "mxtypes.h"

// VTABLE: LEGO1 0x100d6e28
// SIZE 0x154 (from inlined construction at 0x1000a346)
class LegoPathActor : public LegoActor {
public:
	LegoPathActor();

	virtual ~LegoPathActor() override;

	// FUNCTION: LEGO1 0x1000c430
	inline const char* ClassName() const override // vtable+0xc
	{
		// GLOBAL: LEGO1 0x100f0114
		return "LegoPathActor";
	}

	// FUNCTION: LEGO1 0x1000c440
	inline MxBool IsA(const char* name) const override // vtable+0x10
	{
		return !strcmp(name, LegoPathActor::ClassName()) || LegoActor::IsA(name);
	}

	inline void SetUnknownDC(MxU32 p) { m_unkdc = p; }

	virtual void VTable0x68();                         // vtable+0x68
	virtual void VTable0x6c();                         // vtable+0x6c
	virtual void VTable0x70(float p);                  // vtable+0x70
	virtual void VTable0x74(Matrix4Impl& p_transform); // vtable+0x74
	// FUNCTION: LEGO1 0x10002d20
	virtual void VTable0x78(MxU8 p_1) { m_unkea = p_1; } // vtable+0x78
	// FUNCTION: LEGO1 0x10002d30
	virtual MxU8 VTable0x7c() { return m_unkea; } // vtable+0x7c
	virtual void VTable0x80();                    // vtable+0x80
	virtual void VTable0x84();                    // vtable+0x84
	virtual void VTable0x88();                    // vtable+0x88
	virtual void VTable0x8c();                    // vtable+0x8c
	// FUNCTION: LEGO1 0x10002d40
	virtual MxS32 VTable0x90() { return 0; } // vtable+0x90
	// FUNCTION: LEGO1 0x10002d50
	virtual MxS32 VTable0x94() { return 0; } // vtable+0x94
	virtual void VTable0x98();               // vtable+0x98
	virtual void VTable0x9c();               // vtable+0x9c
	// FUNCTION: LEGO1 0x10002d60
	virtual MxS32 VTable0xa0() { return 0; } // vtable+0xa0
	virtual void VTable0xa4();               // vtable+0xa4
	virtual void VTable0xa8();               // vtable+0xa8
	// FUNCTION: LEGO1 0x10002d70
	virtual void VTable0xac(MxFloat p_1) { m_unk140 = p_1; } // vtable+0xac
	// FUNCTION: LEGO1 0x10002d80
	virtual MxFloat VTable0xb0() { return m_unk13c; } // vtable+0xb0
	// FUNCTION: LEGO1 0x10002d90
	virtual MxFloat VTable0xb4() { return m_unk140; } // vtable+0xb4
	// FUNCTION: LEGO1 0x10002da0
	virtual MxFloat VTable0xb8() { return m_unk144; } // vtable+0xb8
	// FUNCTION: LEGO1 0x10002db0
	virtual void VTable0xbc(MxFloat p_1) { m_unk140 = p_1; } // vtable+0xbc
	// FUNCTION: LEGO1 0x10002dc0
	virtual void VTable0xc0(MxFloat p_1) { m_unk144 = p_1; } // vtable+0xc0
	// FUNCTION: LEGO1 0x10002dd0
	virtual void VTable0xc4() {} // vtable+0xc4
	// FUNCTION: LEGO1 0x10002de0
	virtual void VTable0xc8(MxU8 p_1) { m_unk148 = p_1; } // vtable+0xc8

protected:
	// TODO: the types
	undefined m_unk78[0x64];
	MxU32 m_unkdc;
	undefined m_unke0[0xa];
	MxU8 m_unkea;
	undefined m_unk[0x4d];
	MxU32 m_unk138;
	MxFloat m_unk13c;
	MxFloat m_unk140;
	MxFloat m_unk144;
	MxU8 m_unk148;
	MxS32 m_unk14c;
	MxFloat m_unk150;
};

#endif // LEGOPATHACTOR_H
