#ifndef CARRACE_H
#define CARRACE_H

#include "decomp.h"
#include "legorace.h"

// VTABLE: LEGO1 0x100d4b70
// SIZE 0x2c
class CarRaceState : public RaceState {
public:
	// FUNCTION: LEGO1 0x1000dd30
	const char* ClassName() const override // vtable+0x0c
	{
		// STRING: LEGO1 0x100f009c
		return "CarRaceState";
	}

	// FUNCTION: LEGO1 0x1000dd40
	MxBool IsA(const char* p_name) const override // vtable+0x10
	{
		return !strcmp(p_name, CarRaceState::ClassName()) || RaceState::IsA(p_name);
	}

	// SYNTHETIC: LEGO1 0x1000f740
	// CarRaceState::`scalar deleting destructor'
};

// VTABLE: LEGO1 0x100d5e50
// SIZE 0x154
class CarRace : public LegoRace {
public:
	CarRace();

	// FUNCTION: LEGO1 0x10016b20
	const char* ClassName() const override // vtable+0x0c
	{
		// STRING: LEGO1 0x100f0528
		return "CarRace";
	}

	// FUNCTION: LEGO1 0x10016b30
	MxBool IsA(const char* p_name) const override // vtable+0x10
	{
		return !strcmp(p_name, CarRace::ClassName()) || LegoRace::IsA(p_name);
	}

	MxResult Create(MxDSAction& p_dsAction) override;                   // vtable+0x18
	void ReadyWorld() override;                                         // vtable+0x50
	MxBool Escape() override;                                           // vtable+0x64
	MxLong HandleClick(LegoEventNotificationParam&) override;           // vtable+0x6c
	MxLong HandlePathStruct(LegoPathStructNotificationParam&) override; // vtable+0x70
	MxLong HandleEndAction(MxEndActionNotificationParam&) override;     // vtable+0x74
	MxLong HandleType0Notification(MxNotificationParam&) override;      // vtable+0x78

	// SYNTHETIC: LEGO1 0x10016c70
	// CarRace::`scalar deleting destructor'

private:
	undefined m_unk0x144[12]; // 0x144
	undefined4 m_unk0x150;    // 0x150
};

#endif // CARRACE_H
