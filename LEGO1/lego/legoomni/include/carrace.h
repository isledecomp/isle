#ifndef CARRACE_H
#define CARRACE_H

#include "decomp.h"
#include "legorace.h"

// VTABLE: LEGO1 0x100d5e50
// SIZE 0x154
class CarRace : public LegoRace {
public:
	CarRace();

	// FUNCTION: LEGO1 0x10016b20
	inline const char* ClassName() const override // vtable+0x0c
	{
		// STRING: LEGO1 0x100f0528
		return "CarRace";
	}

	// FUNCTION: LEGO1 0x10016b30
	inline MxBool IsA(const char* p_name) const override // vtable+0x10
	{
		return !strcmp(p_name, CarRace::ClassName()) || LegoRace::IsA(p_name);
	}

	MxResult Create(MxDSAction& p_dsAction) override; // vtable+0x18
	void ReadyWorld() override;                       // vtable+0x50
	MxBool VTable0x64() override;                     // vtable+0x64
	undefined4 VTable0x6c(undefined4) override;       // vtable+0x6c
	undefined4 VTable0x70(undefined4) override;       // vtable+0x70
	undefined4 VTable0x74(undefined4) override;       // vtable+0x74
	undefined4 VTable0x78(undefined4) override;       // vtable+0x78

	// SYNTHETIC: LEGO1 0x10016c70
	// CarRace::`scalar deleting destructor'

private:
	undefined m_unk0x144[12]; // 0x144
	undefined4 m_unk0x150;    // 0x150
};

#endif // CARRACE_H
