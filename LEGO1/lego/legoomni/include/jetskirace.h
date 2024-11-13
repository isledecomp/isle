#ifndef JETSKIRACE_H
#define JETSKIRACE_H

#include "legorace.h"

// VTABLE: LEGO1 0x100d4fa8
// VTABLE: BETA10 0x101bd5d0
// SIZE 0x2c
class JetskiRaceState : public RaceState {
public:
	// FUNCTION: LEGO1 0x1000dc40
	// FUNCTION: BETA10 0x100a8f30
	const char* ClassName() const override // vtable+0x0c
	{
		// STRING: LEGO1 0x100f00ac
		// STRING: BETA10 0x101f1d0c
		return "JetskiRaceState";
	}

	// FUNCTION: LEGO1 0x1000dc50
	// FUNCTION: BETA10 0x100a8f60
	MxBool IsA(const char* p_name) const override // vtable+0x10
	{
		return !strcmp(p_name, JetskiRaceState::ClassName()) || RaceState::IsA(p_name);
	}

	// SYNTHETIC: LEGO1 0x1000f680
	// SYNTHETIC: BETA10 0x100a9d10
	// JetskiRaceState::`scalar deleting destructor'
};

// VTABLE: LEGO1 0x100d4fe8
// VTABLE: BETA10 0x101bd268
// SIZE 0x144
class JetskiRace : public LegoRace {
public:
	// FUNCTION: BETA10 0x100a8840
	static const char* HandlerClassName()
	{
		// STRING: LEGO1 0x100f0530
		return "JetskiRace";
	}

	// FUNCTION: LEGO1 0x1000daf0
	// FUNCTION: BETA10 0x100a8810
	const char* ClassName() const override // vtable+0x0c
	{
		return HandlerClassName();
	}

	// FUNCTION: LEGO1 0x1000db00
	// FUNCTION: BETA10 0x100a8860
	MxBool IsA(const char* p_name) const override // vtable+0x10
	{
		return !strcmp(p_name, JetskiRace::ClassName()) || LegoRace::IsA(p_name);
	}

	MxResult Create(MxDSAction& p_dsAction) override;                   // vtable+0x18
	void ReadyWorld() override;                                         // vtable+0x50
	MxBool Escape() override;                                           // vtable+0x64
	MxLong HandleClick(LegoEventNotificationParam&) override;           // vtable+0x6c
	MxLong HandlePathStruct(LegoPathStructNotificationParam&) override; // vtable+0x70
	MxLong HandleEndAction(MxEndActionNotificationParam&) override;     // vtable+0x74

	void FUN_10013670();
};

// SYNTHETIC: LEGO1 0x1000f530
// JetskiRace::`scalar deleting destructor'

#endif // JETSKIRACE_H
