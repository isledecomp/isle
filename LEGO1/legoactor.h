#ifndef LEGOACTOR_H
#define LEGOACTOR_H

#include "decomp.h"
#include "legoentity.h"

// VTABLE: LEGO1 0x100d6d68
// SIZE 0x78
class LegoActor : public LegoEntity {
public:
	LegoActor();

	inline virtual const char* ClassName() const override;      // vtable+0x0c
	inline virtual MxBool IsA(const char* name) const override; // vtable+0x10

	// FUNCTION: LEGO1 0x10002cc0
	virtual MxFloat VTable0x50() { return m_unk68; }
	// FUNCTION: LEGO1 0x10002cd0
	virtual void VTable0x54(MxFloat p_unk) { m_unk68 = p_unk; }
	// FUNCTION: LEGO1 0x10002ce0
	virtual void VTable0x58(MxFloat p_unk) { m_unk70 = p_unk; }
	// FUNCTION: LEGO1 0x10002cf0
	virtual MxFloat VTable0x5c() { return m_unk70; }
	// FUNCTION: LEGO1 0x10002d00
	virtual undefined VTable0x60() { return m_unk74; }
	// FUNCTION: LEGO1 0x10002d10
	virtual void VTable0x64(undefined p_unk) { m_unk74 = p_unk; }

private:
	MxFloat m_unk68;
	undefined4 m_unk6c;
	MxFloat m_unk70;
	undefined m_unk74;
};

#endif // LEGOACTOR_H
