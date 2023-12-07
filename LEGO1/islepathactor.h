#ifndef ISLEPATHACTOR_H
#define ISLEPATHACTOR_H

#include "legopathactor.h"
#include "legoworld.h"
#include "mxtype17notificationparam.h"
#include "mxtype18notificationparam.h"
#include "mxtype19notificationparam.h"
#include "mxtypes.h"

// VTABLE: LEGO1 0x100d4398
// SIZE 0x160
class IslePathActor : public LegoPathActor {
public:
	IslePathActor();

	// FUNCTION: LEGO1 0x10002e70
	virtual MxU32 VTable0xcc() { return 0; } // vtable+0xcc
	// FUNCTION: LEGO1 0x10002df0
	virtual MxU32 VTable0xd0() { return 0; } // vtable+0xd0
	// FUNCTION: LEGO1 0x10002e80
	virtual MxU32 VTable0xd4(MxType17NotificationParam& p) { return 0; } // vtable+0xd4
	// FUNCTION: LEGO1 0x10002e90
	virtual MxU32 VTable0xd8(MxType18NotificationParam& p) { return 0; } // vtable+0xd8
	// FUNCTION: LEGO1 0x10002e00
	virtual MxU32 VTable0xdc(MxType19NotificationParam& p) { return 0; } // vtable+0xdc
	// FUNCTION: LEGO1 0x10002e10
	inline virtual ~IslePathActor() override { IslePathActor::Destroy(TRUE); }

	// FUNCTION: LEGO1 0x10002ea0
	inline virtual const char* ClassName() const override // vtable+0x0c
	{
		// GLOBAL: LEGO1 0x100f0104
		return "IslePathActor";
	}

	// FUNCTION: LEGO1 0x10002eb0
	inline virtual MxBool IsA(const char* name) const override // vtable+0x10
	{
		return !strcmp(name, IslePathActor::ClassName()) || LegoPathActor::IsA(name);
	}

	// SYNTHETIC: LEGO1 0x10002ff0
	// IslePathActor::`scalar deleting destructor'

	virtual MxResult Create(MxDSObject& p_dsObject) override; // vtable+0x18
	virtual void VTable0xe0();                                // vtable+0xe0
	virtual void VTable0xe4();                                // vtable+0xe4
	virtual void VTable0xe8(MxU32 p_1, MxBool p_2, MxU8 p_3); // vtable+0xe8
	virtual void VTable0xec();                                // vtable+0xec

	inline void SetWorld(LegoWorld* p_world) { m_LegoWorld = p_world; }
	inline LegoWorld* GetWorld() { return m_LegoWorld; }

protected:
	LegoWorld* m_LegoWorld; // 0x154
	MxFloat m_unk158;
	MxFloat m_unk15c;
};

#endif // ISLEPATHACTOR_H
