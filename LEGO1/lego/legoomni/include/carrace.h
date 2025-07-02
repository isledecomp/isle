#ifndef CARRACE_H
#define CARRACE_H

#include "decomp.h"
#include "legorace.h"

class RaceSkel;

// VTABLE: LEGO1 0x100d4b70
// VTABLE: BETA10 0x101bd5f0
// SIZE 0x2c
class CarRaceState : public RaceState {
public:
	// FUNCTION: LEGO1 0x1000dd30
	// FUNCTION: BETA10 0x100a9100
	const char* ClassName() const override // vtable+0x0c
	{
		// STRING: LEGO1 0x100f009c
		return "CarRaceState";
	}

	// FUNCTION: LEGO1 0x1000dd40
	// FUNCTION: BETA10 0x100a9130
	MxBool IsA(const char* p_name) const override // vtable+0x10
	{
		return !strcmp(p_name, CarRaceState::ClassName()) || RaceState::IsA(p_name);
	}

	// SYNTHETIC: LEGO1 0x1000f740
	// CarRaceState::`scalar deleting destructor'
};

// VTABLE: LEGO1 0x100d5e50
// VTABLE: BETA10 0x101be290
// SIZE 0x154
class CarRace : public LegoRace {
public:
	CarRace();

	// FUNCTION: LEGO1 0x10016b20
	// FUNCTION: BETA10 0x100c9870
	const char* ClassName() const override // vtable+0x0c
	{
		// STRING: LEGO1 0x100f0528
		return "CarRace";
	}

	// FUNCTION: LEGO1 0x10016b30
	// FUNCTION: BETA10 0x100c98a0
	MxBool IsA(const char* p_name) const override // vtable+0x10
	{
		return !strcmp(p_name, CarRace::ClassName()) || LegoRace::IsA(p_name);
	}

	MxResult Create(MxDSAction& p_dsAction) override;                    // vtable+0x18
	void ReadyWorld() override;                                          // vtable+0x50
	MxBool Escape() override;                                            // vtable+0x64
	MxLong HandleControl(LegoControlManagerNotificationParam&) override; // vtable+0x6c
	MxLong HandlePathStruct(LegoPathStructNotificationParam&) override;  // vtable+0x70
	MxLong HandleEndAction(MxEndActionNotificationParam&) override;      // vtable+0x74
	MxLong HandleType0Notification(MxNotificationParam&) override;       // vtable+0x78

	// FUNCTION: BETA10 0x100cd060
	RaceSkel* GetSkeleton() { return m_skeleton; }

	// FUNCTION: BETA10 0x100f16f0
	void SetSkeleton(RaceSkel* p_skeleton) { m_skeleton = p_skeleton; }

	void FUN_10017820(MxS32 p_param1, MxS16 p_param2);

	// SYNTHETIC: LEGO1 0x10016c70
	// CarRace::`scalar deleting destructor'

private:
	static MxS32 g_unk0x100d5d10[];
	static MxS32 g_unk0x100d5d30[];
	static MxS32 g_unk0x100d5d40[];
	static MxS32 g_unk0x100d5d50[];
	static MxS32 g_unk0x100d5d60[];

	MxS32 m_unk0x144;     // 0x144
	MxS32 m_unk0x148;     // 0x148
	MxS32 m_unk0x14c;     // 0x14c
	RaceSkel* m_skeleton; // 0x150
};

#endif // CARRACE_H
