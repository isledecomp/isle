#ifndef PIZZERIA_H
#define PIZZERIA_H

#include "decomp.h"
#include "isleactor.h"

// VTABLE: LEGO1 0x100d5520
// SIZE 0x84
class Pizzeria : public IsleActor {
public:
	Pizzeria() : m_unk0x7c(0) {}

	// FUNCTION: LEGO1 0x1000e780
	inline const char* ClassName() const override // vtable+0x0c
	{
		// STRING: LEGO1 0x100f0380
		return "Pizzeria";
	}

	// FUNCTION: LEGO1 0x1000e790
	inline MxBool IsA(const char* p_name) const override // vtable+0x10
	{
		return !strcmp(p_name, Pizzeria::ClassName()) || IsleActor::IsA(p_name);
	}

	MxResult Create(MxDSAction& p_dsAction) override; // vtable+0x18
	undefined4 VTable0x68() override;                 // vtable+0x68

	// SYNTHETIC: LEGO1 0x1000e8d0
	// Pizzeria::`scalar deleting destructor'

private:
	undefined4 m_unk0x7c; // 0x7c
	undefined4 m_unk0x80; // 0x80
};

#endif // PIZZERIA_H
