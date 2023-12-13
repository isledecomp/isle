#ifndef ISLEPATHACTOR_H
#define ISLEPATHACTOR_H

#include "legopathactor.h"
#include "legoworld.h"
#include "mxtypes.h"

// VTABLE: LEGO1 0x100d4398
// SIZE 0x160
class IslePathActor : public LegoPathActor {
public:
	IslePathActor();

	// FUNCTION: LEGO1 0x10002ea0
	inline virtual const char* ClassName() const override // vtable+0x0c
	{
		// GLOBAL: LEGO1 0x100f0104
		return "IslePathActor";
	}

	// FUNCTION: LEGO1 0x10002eb0
	inline virtual MxBool IsA(const char* p_name) const override // vtable+0x10
	{
		return !strcmp(p_name, IslePathActor::ClassName()) || LegoPathActor::IsA(p_name);
	}

	// SYNTHETIC: LEGO1 0x10002ff0
	// IslePathActor::`scalar deleting destructor'
	inline virtual ~IslePathActor() override { IslePathActor::Destroy(TRUE); }

	virtual MxResult Create(MxDSObject& p_dsObject) override; // vtable+0x18
	virtual void VTable0xcc();                                // vtable+0xcc
	virtual void VTable0xd0();                                // vtable+0xd0
	virtual void VTable0xd4();                                // vtable+0xd4
	virtual void VTable0xd8();                                // vtable+0xd8
	virtual void VTable0xdc();                                // vtable+0xdc
	virtual void VTable0xe0();                                // vtable+0xe0
	virtual void VTable0xe4();                                // vtable+0xe4
	virtual void VTable0xe8(MxU32, MxBool, MxU8);             // vtable+0xe8
	virtual void VTable0xec();                                // vtable+0xec

	inline void SetWorld(LegoWorld* p_world) { m_world = p_world; }
	inline LegoWorld* GetWorld() { return m_world; }

private:
	LegoWorld* m_world; // 0x154
	MxFloat m_unk0x158;
	MxFloat m_unk0x15c;
};

#endif // ISLEPATHACTOR_H
