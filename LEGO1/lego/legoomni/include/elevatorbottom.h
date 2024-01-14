#ifndef ELEVATORBOTTOM_H
#define ELEVATORBOTTOM_H

#include "decomp.h"
#include "legoworld.h"

// VTABLE: LEGO1 0x100d5f20
// SIZE: 0xfc (from inlined ctor at 0x1000a8aa)
class ElevatorBottom : public LegoWorld {
public:
	ElevatorBottom();
	virtual ~ElevatorBottom() override; // vtable+0x0

	virtual MxLong Notify(MxParam& p_param) override; // vtable+0x4

	// FUNCTION: LEGO1 0x10017f20
	inline virtual const char* ClassName() const override // vtable+0x0c
	{
		// STRING: LEGO1 0x100f04ac
		return "ElevatorBottom";
	}

	// FUNCTION: LEGO1 0x10017f30
	inline virtual MxBool IsA(const char* p_name) const override // vtable+0x10
	{
		return !strcmp(p_name, ElevatorBottom::ClassName()) || LegoWorld::IsA(p_name);
	}

private:
	undefined4 m_unk0xf8; // 0xf8
};

#endif // ELEVATORBOTTOM_H
