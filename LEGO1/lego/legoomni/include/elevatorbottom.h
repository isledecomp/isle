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

	virtual MxResult Create(MxDSAction& p_dsAction) override; // vtable+0x18
	virtual void VTable0x50() override;                       // vtable+0x50

	// FUNCTION: LEGO1 0x10017f10
	virtual MxBool VTable0x5c() override { return TRUE; } // vtable+0x5c

	virtual MxBool VTable0x64() override;           // vtable+0x64
	virtual void VTable0x68(MxBool p_add) override; // vtable+0x68

	// SYNTHETIC: LEGO1 0x10018040
	// ElevatorBottom::`scalar deleting destructor'

private:
	undefined4 m_unk0xf8; // 0xf8

	MxLong HandleNotification17(MxParam& p_param);
};

#endif // ELEVATORBOTTOM_H
