#ifndef PIZZA_H
#define PIZZA_H

#include "decomp.h"
#include "isleactor.h"
#include "mxactionnotificationparam.h"

// VTABLE: LEGO1 0x100d7380
// SIZE 0x9c
class Pizza : public IsleActor {
public:
	Pizza();
	~Pizza() override;

	MxResult Tickle() override; // vtable+0x08

	// FUNCTION: LEGO1 0x10037f90
	inline const char* ClassName() const override // vtable+0x0c
	{
		// STRING: LEGO1 0x100f038c
		return "Pizza";
	}

	// FUNCTION: LEGO1 0x10037fa0
	inline MxBool IsA(const char* p_name) const override // vtable+0x10
	{
		return !strcmp(p_name, Pizza::ClassName()) || IsleActor::IsA(p_name);
	}

	MxResult Create(MxDSAction& p_dsAction) override; // vtable+0x18

	// STUB: LEGO1 0x100383f0
	undefined4 VTable0x68() override { return 0; } // vtable+0x68

	// STUB: LEGO1 0x1003b10
	undefined4 HandleEndAction(MxEndActionNotificationParam&) override { return 0; } // vtable+0x74

	// STUB: LEGO1 0x100384f0
	undefined4 VTable0x80(MxParam&) override { return 0; } // vtable+0x80

	// SYNTHETIC: LEGO1 0x100380e0
	// Pizza::`scalar deleting destructor'

private:
	undefined4 m_unk0x7c;
	undefined4 m_unk0x80;
	undefined4 m_unk0x84;
	undefined4 m_unk0x88;
	undefined4 m_unk0x8c;
	undefined4 m_unk0x90;
	undefined4 m_unk0x94;
	undefined m_unk0x98;
};

#endif // PIZZA_H
