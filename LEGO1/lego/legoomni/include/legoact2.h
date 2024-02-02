#ifndef LEGOACT2_H
#define LEGOACT2_H

#include "legocarraceactor.h"
#include "legopathactor.h"
#include "legoworld.h"

// VTABLE: LEGO1 0x100d82e0
// SIZE 0x1154
class LegoAct2 : public LegoWorld {

	MxLong Notify(MxParam& p_param) override;         // vtable+0x04
	MxResult Tickle() override;                       // vtable+0x08
	MxResult Create(MxDSAction& p_dsAction) override; // vtable+0x18
	void ReadyWorld() override;                       // vtable+0x50
	MxBool VTable0x5c() override;                     // vtable+0x5c
	void VTable0x60() override;                       // vtable+0x60
	MxBool VTable0x64() override;                     // vtable+0x64
	void Enable(MxBool p_enable) override;            // vtable+0x68

	// SYNTHETIC: LEGO1 0x1004fe20
	// LegoAct2::`scalar deleting destructor'
};

#endif // LEGOACT2_H
