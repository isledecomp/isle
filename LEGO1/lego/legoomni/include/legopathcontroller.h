#ifndef LEGOPATHCONTROLLER_H
#define LEGOPATHCONTROLLER_H

#include "decomp.h"
#include "legopathactor.h"
#include "mxcore.h"

class LegoPathBoundary;
class LegoWorld;

struct LegoPathControllerComparator {
	MxBool operator()(const undefined*, const undefined*) const { return 0; }
};

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

	virtual void VTable0x14(MxU8* p_data, Vector3& p_location, MxAtomId& p_trigger); // vtable+0x14
	virtual void Destroy();                                                          // vtable+0x18

	undefined4 FUN_10046770(LegoPathActor* p_actor);
	MxResult FUN_10046b30(LegoPathBoundary** p_path, MxS32& p_value);
	void Enable(MxBool p_enable);
	void FUN_10046bb0(LegoWorld* p_world);

private:
	LegoPathBoundary* m_unk0x08;                                         // 0x08
	undefined4 m_unk0x0c;                                                // 0x0c
	undefined4 m_unk0x10;                                                // 0x10
	undefined4 m_unk0x14;                                                // 0x14
	MxS16 m_numL;                                                        // 0x18
	MxS16 m_numE;                                                        // 0x1a
	MxS16 m_numN;                                                        // 0x1c
	MxS16 m_numT;                                                        // 0x1e
	map<undefined*, undefined*, LegoPathControllerComparator> m_pfsE;    // 0x20
	map<undefined*, undefined*, LegoPathControllerComparator> m_unk0x30; // 0x30
};

#endif // LEGOPATHCONTROLLER_H
