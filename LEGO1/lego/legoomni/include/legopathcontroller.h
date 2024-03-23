#ifndef LEGOPATHCONTROLLER_H
#define LEGOPATHCONTROLLER_H

#include "decomp.h"
#include "legopathactor.h"
#include "mxcore.h"
class LegoPathBoundary;

// VTABLE: LEGO1 0x100d7d60
// SIZE 0x40
class LegoPathController : public MxCore {
public:
	LegoPathController();
	~LegoPathController() override { Destroy(); }

	MxResult Tickle() override; // vtable+08

	// FUNCTION: LEGO1 0x10045110
	inline const char* ClassName() const override // vtable+0x0c
	{
		// STRING: LEGO1 0x100f11b8
		return "LegoPathController";
	}

	// FUNCTION: LEGO1 0x10045120
	inline MxBool IsA(const char* p_name) const override // vtable+0x10
	{
		return !strcmp(p_name, LegoPathController::ClassName()) || MxCore::IsA(p_name);
	}

	// SYNTHETIC: LEGO1 0x10045740
	// LegoPathController::`scalar deleting destructor'

	virtual void VTable0x14(); // vtable+0x14
	virtual void Destroy();    // vtable+0x18

	undefined4 FUN_10046770(LegoPathActor* p_actor);
	MxResult FUN_10046b30(LegoPathBoundary** p_path, MxS32& p_value);
	void Enable(MxBool p_enable);

private:
	undefined4 m_unk0x08; // 0x08
	undefined4 m_unk0x0c; // 0x0c
	undefined4 m_unk0x10; // 0x10
	undefined4 m_unk0x14; // 0x14
	undefined2 m_unk0x18; // 0x18
	undefined2 m_unk0x1a; // 0x1a
	undefined2 m_unk0x1c; // 0x1c
	undefined2 m_unk0x1e; // 0x1e
	// These 2 are some sort of template class
	undefined m_unk0x20[0x10]; // 0x20
	undefined m_unk0x30[0x10]; // 0x30
};

#endif // LEGOPATHCONTROLLER_H
