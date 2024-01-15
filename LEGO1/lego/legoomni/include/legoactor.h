#ifndef LEGOACTOR_H
#define LEGOACTOR_H

#include "decomp.h"
#include "legoentity.h"

// VTABLE: LEGO1 0x100d6d68
// SIZE 0x78
class LegoActor : public LegoEntity {
public:
	LegoActor();
	virtual ~LegoActor() override;

	// FUNCTION: LEGO1 0x1002d210
	inline virtual const char* ClassName() const override // vtable+0x0c
	{
		// STRING: LEGO1 0x100f0124
		return "LegoActor";
	}

	// FUNCTION: LEGO1 0x1002d220
	inline virtual MxBool IsA(const char* p_name) const override // vtable+0x10
	{
		return !strcmp(p_name, LegoActor::ClassName()) || LegoEntity::IsA(p_name);
	}

	// FUNCTION: LEGO1 0x10002cc0
	virtual MxFloat VTable0x50() { return m_unk0x68; } // vtable+0x50
	// FUNCTION: LEGO1 0x10002cd0
	virtual void VTable0x54(MxFloat p_unk0x68) { m_unk0x68 = p_unk0x68; } // vtable+0x54
	// FUNCTION: LEGO1 0x10002ce0
	virtual void VTable0x58(MxFloat p_unk0x70) { m_unk0x70 = p_unk0x70; } // vtable+0x58
	// FUNCTION: LEGO1 0x10002cf0
	virtual MxFloat VTable0x5c() { return m_unk0x70; } // vtable+0x5c
	// FUNCTION: LEGO1 0x10002d00
	virtual MxU8 VTable0x60() { return m_unk0x74; } // vtable+0x60
	// FUNCTION: LEGO1 0x10002d10
	virtual void VTable0x64(MxU8 p_unk0x74) { m_unk0x74 = p_unk0x74; } // vtable+0x64

private:
	MxFloat m_unk0x68;    // 0x68
	undefined4 m_unk0x6c; // 0x6c
	MxFloat m_unk0x70;    // 0x70
	MxU8 m_unk0x74;       // 0x74
};

// SYNTHETIC: LEGO1 0x1002d300
// LegoActor::`scalar deleting destructor'

#endif // LEGOACTOR_H
