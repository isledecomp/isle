#ifndef LEGORACE_H
#define LEGORACE_H

#include "decomp.h"
#include "legoworld.h"
#include "mxrect32.h"
#include "mxtypes.h"

// VTABLE: LEGO1 0x100d5db0
// SIZE 0x144
class LegoRace : public LegoWorld {
public:
	LegoRace();
	virtual ~LegoRace() override; // vtable+0x0

	virtual MxLong Notify(MxParam& p_param) override; // vtable+0x4

	// FUNCTION: LEGO1 0x10015ba0
	inline const char* ClassName() const override // vtable+0xc
	{
		// STRING: LEGO1 0x100f07c4
		return "LegoRace";
	}

	// FUNCTION: LEGO1 0x10015bb0
	inline MxBool IsA(const char* p_name) const override // vtable+0x10
	{
		return !strcmp(p_name, LegoRace::ClassName()) || LegoWorld::IsA(p_name);
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
	undefined4 m_unk0xf8;  // 0xf8
	undefined4 m_unk0xfc;  // 0xfc
	undefined4 m_unk0x100; // 0x100
	undefined4 m_unk0x104; // 0x104
	undefined4 m_unk0x108; // 0x108
	undefined4 m_unk0x10c; // 0x10c
	undefined4 m_unk0x110; // 0x110
	undefined4 m_unk0x114; // 0x114
	undefined4 m_unk0x118; // 0x118
	undefined4 m_unk0x11c; // 0x11c
	undefined4 m_unk0x120; // 0x120
	undefined4 m_unk0x124; // 0x124
	undefined4 m_unk0x128; // 0x128
	undefined4 m_unk0x12c; // 0x12c

protected:
	MxRect32 m_unk0x130; // 0x130

private:
	undefined4 m_unk0x140; // 0x140
};

#endif // LEGORACE_H
