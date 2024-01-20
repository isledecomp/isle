#ifndef LEGOACT2_H
#define LEGOACT2_H

#include "legocarraceactor.h"
#include "legopathactor.h"
#include "legoworld.h"

// VTABLE: LEGO1 0x100d82e0
// SIZE 0x1154
class LegoAct2 : public LegoWorld {

	virtual MxLong Notify(MxParam& p_param) override;         // vtable+0x04
	virtual MxResult Tickle() override;                       // vtable+0x08
	virtual MxResult Create(MxDSAction& p_dsAction) override; // vtable+0x18
	virtual void VTable0x50() override;                       // vtable+0x50
	virtual MxBool VTable0x5c() override;                     // vtable+0x5c
	virtual void VTable0x60() override;                       // vtable+0x60
	virtual MxBool VTable0x64() override;                     // vtable+0x64
	virtual void VTable0x68(MxBool p_add) override;           // vtable+0x68

	// SYNTHETIC: LEGO1 0x1004fe20
	// LegoAct2::`scalar deleting destructor'
};

#endif // LEGOACT2_H
