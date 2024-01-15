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

	// FUNCTION: LEGO1 0x10002e10
	inline virtual ~IslePathActor() override { IslePathActor::Destroy(TRUE); } // vtable+0x0

	// FUNCTION: LEGO1 0x10002ea0
	inline virtual const char* ClassName() const override // vtable+0x0c
	{
		// STRING: LEGO1 0x100f0104
		return "IslePathActor";
	}

	// FUNCTION: LEGO1 0x10002eb0
	inline virtual MxBool IsA(const char* p_name) const override // vtable+0x10
	{
		return !strcmp(p_name, IslePathActor::ClassName()) || LegoPathActor::IsA(p_name);
	}

	virtual MxResult Create(MxDSAction& p_dsAction) override; // vtable+0x18
	virtual void Destroy(MxBool p_fromDestructor) override;   // vtable+0x1c
	// FUNCTION: LEGO1 0x10002e70
	virtual MxU32 VTable0xcc() { return 0; } // vtable+0xcc
	// FUNCTION: LEGO1 0x10002df0
	virtual MxU32 VTable0xd0() { return 0; } // vtable+0xd0
	// FUNCTION: LEGO1 0x10002e80
	virtual MxU32 VTable0xd4(MxType17NotificationParam&) { return 0; } // vtable+0xd4
	// FUNCTION: LEGO1 0x10002e90
	virtual MxU32 VTable0xd8(MxType18NotificationParam&) { return 0; } // vtable+0xd8
	// FUNCTION: LEGO1 0x10002e00
	virtual MxU32 VTable0xdc(MxType19NotificationParam&) { return 0; } // vtable+0xdc
	virtual void VTable0xe0();                                         // vtable+0xe0
	virtual void VTable0xe4();                                         // vtable+0xe4
	virtual void VTable0xe8(MxU32, MxBool, MxU8);                      // vtable+0xe8
	virtual void VTable0xec();                                         // vtable+0xec

	// SYNTHETIC: LEGO1 0x10002ff0
	// IslePathActor::`scalar deleting destructor'

	inline void SetWorld(LegoWorld* p_world) { m_world = p_world; }
	inline LegoWorld* GetWorld() { return m_world; }

protected:
	LegoWorld* m_world; // 0x154
	MxFloat m_unk0x158; // 0x158
	MxFloat m_unk0x15c; // 0x15c
};

#endif // ISLEPATHACTOR_H
