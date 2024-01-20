#ifndef GASSTATION_H
#define GASSTATION_H

#include "decomp.h"
#include "legoworld.h"
#include "radio.h"

// VTABLE: LEGO1 0x100d4650
// SIZE 0x128
// Radio variable at 0x46, in constructor
class GasStation : public LegoWorld {
public:
	GasStation();
	virtual ~GasStation() override; // vtable+0x0

	virtual MxLong Notify(MxParam& p_param) override; // vtable+0x4
	virtual MxResult Tickle() override;               // vtable+0x8

	// FUNCTION: LEGO1 0x10004780
	inline virtual const char* ClassName() const override // vtable+0x0c
	{
		// STRING: LEGO1 0x100f0168
		return "GasStation";
	}

	// FUNCTION: LEGO1 0x10004790
	inline virtual MxBool IsA(const char* p_name) const override // vtable+0x10
	{
		return !strcmp(p_name, GasStation::ClassName()) || LegoWorld::IsA(p_name);
	}

	virtual MxResult Create(MxDSAction& p_dsAction) override; // vtable+0x18
	virtual void VTable0x50() override;                       // vtable+0x50
	virtual MxBool VTable0x5c() override;                     // vtable+0x5c
	virtual MxBool VTable0x64() override;                     // vtable+0x64
	virtual void VTable0x68(MxBool p_add) override;           // vtable+0x68

	// SYNTHETIC: LEGO1 0x100048a0
	// GasStation::`scalar deleting destructor'

private:
	undefined2 m_unk0xf8;  // 0xf8
	undefined2 m_unk0xfa;  // 0xfa
	undefined4 m_unk0xfc;  // 0xfc
	undefined4 m_unk0x100; // 0x100
	undefined2 m_unk0x104; // 0x104
	undefined2 m_unk0x106; // 0x106
	undefined4 m_unk0x108; // 0x108
	undefined4 m_unk0x10c; // 0x10c
	undefined4 m_unk0x110; // 0x110
	undefined m_unk0x114;  // 0x114
	undefined m_unk0x115;  // 0x115
	Radio m_radio;         // 0x118
};

#endif // GASSTATION_H
