#ifndef PIZZERIA_H
#define PIZZERIA_H

#include "actionsfwd.h"
#include "decomp.h"
#include "isleactor.h"
#include "legostate.h"

class PizzaMissionState;

// VTABLE: LEGO1 0x100d5ee8
// VTABLE: BETA10 0x101bf788
// SIZE 0x58
class PizzeriaState : public LegoState {
public:
	PizzeriaState();

	// FUNCTION: LEGO1 0x10017c20
	// FUNCTION: BETA10 0x100f0020
	const char* ClassName() const override // vtable+0x0c
	{
		// STRING: LEGO1 0x100f0370
		return "PizzeriaState";
	}

	// FUNCTION: LEGO1 0x10017c30
	MxBool IsA(const char* p_name) const override // vtable+0x10
	{
		return !strcmp(p_name, PizzeriaState::ClassName()) || LegoState::IsA(p_name);
	}

	MxResult Serialize(LegoFile* p_file) override; // vtable+0x1c

	// SYNTHETIC: LEGO1 0x10017ce0
	// PizzeriaState::`scalar deleting destructor'

	MxS16 FUN_10017d50();
	MxU32 NextAction();

	Playlist m_unk0x08[5]; // 0x08
	MxS32 m_unk0x44[5];    // 0x44

	static IsleScript::Script g_pepperActions[];
	static IsleScript::Script g_mamaActions[];
	static IsleScript::Script g_papaActions[];
	static IsleScript::Script g_nickActions[];
	static IsleScript::Script g_lauraActions[];
};

// VTABLE: LEGO1 0x100d5520
// VTABLE: BETA10 0x101bd0b0
// SIZE 0x84
class Pizzeria : public IsleActor {
public:
	Pizzeria() : m_pizzeriaState(NULL) {}

	// FUNCTION: LEGO1 0x1000e780
	// FUNCTION: BETA10 0x100a81f0
	const char* ClassName() const override // vtable+0x0c
	{
		// STRING: LEGO1 0x100f0380
		return "Pizzeria";
	}

	// FUNCTION: LEGO1 0x1000e790
	MxBool IsA(const char* p_name) const override // vtable+0x10
	{
		return !strcmp(p_name, Pizzeria::ClassName()) || IsleActor::IsA(p_name);
	}

	MxResult Create(MxDSAction& p_dsAction) override; // vtable+0x18
	MxLong HandleClick() override;                    // vtable+0x68

	void CreateState();

	// SYNTHETIC: LEGO1 0x1000e8d0
	// Pizzeria::`scalar deleting destructor'

private:
	PizzeriaState* m_pizzeriaState;         // 0x7c
	PizzaMissionState* m_pizzaMissionState; // 0x80
};

#endif // PIZZERIA_H
