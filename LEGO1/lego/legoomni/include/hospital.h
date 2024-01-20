#ifndef HOSPITAL_H
#define HOSPITAL_H

#include "decomp.h"
#include "legoworld.h"

// VTABLE: LEGO1 0x100d9730
// SIZE 0x12c
class Hospital : public LegoWorld {
public:
	Hospital();
	virtual ~Hospital() override; // vtable+0x0

	virtual MxLong Notify(MxParam& p_param) override; // vtable+0x04
	virtual MxResult Tickle() override;               // vtable+0x08

	// FUNCTION: LEGO1 0x100746b0
	inline virtual const char* ClassName() const override // vtable+0x0c
	{
		// STRING: LEGO1 0x100f0490
		return "Hospital";
	}

	// FUNCTION: LEGO1 0x100746c0
	inline virtual MxBool IsA(const char* p_name) const override // vtable+0x10
	{
		return !strcmp(p_name, Hospital::ClassName()) || LegoWorld::IsA(p_name);
	}

	virtual MxResult Create(MxDSAction& p_dsAction) override; // vtable+0x18
	virtual void VTable0x50() override;                       // vtable+0x50
	virtual MxBool VTable0x5c() override;                     // vtable+0x5c
	virtual MxBool VTable0x64() override;                     // vtable+0x64
	virtual void VTable0x68(MxBool p_add) override;           // vtable+0x68

	// SYNTHETIC: LEGO1 0x100747d0
	// Hospital::`scalar deleting destructor'

private:
	undefined2 m_unk0xf8;    // 0xf8
	undefined4 m_unk0xfc;    // 0xfc
	undefined2 m_unk0x100;   // 0x100
	undefined4 m_unk0x104;   // 0x104 - VTable0x18 suggests this may be pointer to a LegoGameState
	undefined2 m_unk0x108;   // 0x108
	undefined4 m_unk0x10c;   // 0x10c
	undefined4 m_unk0x110;   // 0x110
	undefined4 m_unk0x114;   // 0x114
	undefined m_unk0x118;    // 0x118
	undefined4 m_unk0x11c;   // 0x11c
	undefined4 m_unk0x120;   // 0x120
	undefined m_unk0x124[4]; // 0x124
	undefined m_unk0x128;    // 0x128
};

#endif // HOSPITAL_H
