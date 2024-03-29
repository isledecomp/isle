#ifndef LEGOACT2_H
#define LEGOACT2_H

#include "act2brick.h"
#include "legocarraceactor.h"
#include "legopathactor.h"
#include "legoworld.h"

// VTABLE: LEGO1 0x100d82e0
// SIZE 0x1154
class LegoAct2 : public LegoWorld {
public:
	MxLong Notify(MxParam& p_param) override;         // vtable+0x04
	MxResult Tickle() override;                       // vtable+0x08
	MxResult Create(MxDSAction& p_dsAction) override; // vtable+0x18
	void ReadyWorld() override;                       // vtable+0x50
	MxBool VTable0x5c() override;                     // vtable+0x5c
	void VTable0x60() override;                       // vtable+0x60
	MxBool VTable0x64() override;                     // vtable+0x64
	void Enable(MxBool p_enable) override;            // vtable+0x68

	inline void SetUnknown0x1150(undefined4 p_unk0x1150) { m_unk0x1150 = p_unk0x1150; }

	// SYNTHETIC: LEGO1 0x1004fe20
	// LegoAct2::`scalar deleting destructor'

private:
	Act2Brick m_bricks[10];      // 0x00f8
	undefined m_unk0x10c0;       // 0x10c0
	undefined m_unk0x10c1;       // 0x10c1
	undefined m_unk0x10c2;       // 0x10c2
	undefined4 m_unk0x10c4;      // 0x10c4
	undefined4 m_unk0x10c8;      // 0x10c8
	undefined4 m_unk0x10cc;      // 0x10cc
	undefined4 m_unk0x10d0;      // 0x10d0
	char* m_unk0x10d4;           // 0x10d4
	undefined4 m_unk0x10d8;      // 0x10d8
	MxMatrix m_unk0x10dc;        // 0x10dc
	undefined4 m_unk0x1124;      // 0x1124
	undefined4 m_unk0x1128;      // 0x1128
	undefined4 m_unk0x112c;      // 0x112c
	undefined4 m_unk0x1130;      // 0x1130
	undefined4 m_unk0x1134;      // 0x1134
	undefined4 m_unk0x1138;      // 0x1138
	undefined m_unk0x113c;       // 0x113c
	undefined4 m_unk0x1140;      // 0x1140
	undefined4 m_unk0x1144;      // 0x1144
	undefined m_unk0x1148[0x08]; // 0x1148
	undefined4 m_unk0x1150;      // 0x1150
};

#endif // LEGOACT2_H
