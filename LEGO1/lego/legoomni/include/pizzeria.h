#ifndef PIZZERIA_H
#define PIZZERIA_H

#include "decomp.h"
#include "isleactor.h"
#include "legostate.h"

class PizzaMissionState;

// VTABLE: LEGO1 0x100d5ee8
// SIZE 0x58
class PizzeriaState : public LegoState {
public:
	// SIZE 0x14
	struct StateStruct {
		undefined4 m_unk0x00; // 0x00
		undefined4 m_unk0x04; // 0x04
		undefined4 m_unk0x08; // 0x08
		undefined4 m_unk0x0c; // 0x0c
		undefined4 m_unk0x10; // 0x10
	};

	PizzeriaState();

	// FUNCTION: LEGO1 0x10017c20
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
	MxU32 FUN_10017d70();

	// TODO: Most likely getters/setters are not used according to BETA.

	Playlist m_unk0x08[5]; // 0x08
	StateStruct m_unk0x44; // 0x44
};

// VTABLE: LEGO1 0x100d5520
// SIZE 0x84
class Pizzeria : public IsleActor {
public:
	Pizzeria() : m_pizzeriaState(NULL) {}

	// FUNCTION: LEGO1 0x1000e780
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
