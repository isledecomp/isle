#ifndef LEGORACE_H
#define LEGORACE_H

#include "decomp.h"
#include "legoworld.h"
#include "mxtypes.h"

// VTABLE: LEGO1 0x100d5db0
// SIZE 0x144
class LegoRace : public LegoWorld {
public:
	LegoRace();
	virtual ~LegoRace() override; // vtable+0x0

	virtual MxLong Notify(MxParam& p) override; // vtable+0x4

	// FUNCTION: LEGO1 0x10015ba0
	inline const char* ClassName() const override // vtable+0xc
	{
		// 0x100f07c4
		return "LegoRace";
	}

	// FUNCTION: LEGO1 0x10015bb0
	inline MxBool IsA(const char* name) const override // vtable+0x10
	{
		return !strcmp(name, LegoRace::ClassName()) || LegoWorld::IsA(name);
	}

	virtual MxResult Create(MxDSObject& p_dsObject) override; // vtable+0x18
	virtual MxBool VTable0x5c() override;                     // vtable+0x5c
	virtual MxBool VTable0x64() override;                     // vtable+0x64
	virtual void VTable0x68(MxBool p_add) override;           // vtable+0x68
	virtual undefined4 VTable0x6c(undefined4) = 0;            // vtable+0x6c
	virtual undefined4 VTable0x70(undefined4);                // vtable+0x70
	virtual undefined4 VTable0x74(undefined4);                // vtable+0x74
	virtual undefined4 VTable0x78(undefined4);                // vtable+0x78
	virtual void VTable0x7c(undefined4, undefined4);          // vtable+0x7c

private:
	undefined4 m_unkf8;     // 0xf8
	undefined4 m_unkfc;     // 0xfc
	undefined4 m_unk100;    // 0x100
	undefined4 m_unk104;    // 0x104
	undefined4 m_unk108;    // 0x108
	undefined4 m_unk10c;    // 0x10c
	undefined4 m_unk110;    // 0x110
	undefined4 m_unk114;    // 0x114
	undefined4 m_unk118;    // 0x118
	undefined4 m_unk11c;    // 0x11c
	undefined4 m_unk120;    // 0x120 - this may be the current vehcle (function at 0x10015880)
	undefined4 m_unk124;    // 0x124 - something game state
	undefined4 m_unk128;    // 0x128
	undefined4 m_unk12c;    // 0x12c
	undefined4 m_unk130[4]; // unconfirmed bytes, ghidra claims these are integers
	undefined4 m_unk140;
};

#endif // LEGORACE_H
