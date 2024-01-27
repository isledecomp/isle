#ifndef LEGOWORLD_H
#define LEGOWORLD_H

#include "legocachesound.h"
#include "legocachesoundlist.h"
#include "legocameracontroller.h"
#include "legoentity.h"
#include "legoentitylist.h"
#include "legopathcontrollerlist.h"
#include "mxpresenter.h"
#include "mxpresenterlist.h"

class IslePathActor;
class LegoPathBoundary;
class LegoHideAnimPresenter;

struct CoreSetCompare {
	MxS32 operator()(MxCore* const& p_a, MxCore* const& p_b) const { return (MxS32) p_a < (MxS32) p_b; }
};

typedef set<MxCore*, CoreSetCompare> MxCoreSet;

// VTABLE: LEGO1 0x100d6280
// SIZE 0xf8
class LegoWorld : public LegoEntity {
public:
	LegoWorld();
	virtual ~LegoWorld() override; // vtable+0x0

	virtual MxLong Notify(MxParam& p_param) override; // vtable+0x4
	virtual MxResult Tickle() override;               // vtable+0x8

	// FUNCTION: LEGO1 0x1001d690
	inline virtual const char* ClassName() const override // vtable+0x0c
	{
		// STRING: LEGO1 0x100f0058
		return "LegoWorld";
	}

	// FUNCTION: LEGO1 0x1001d6a0
	inline virtual MxBool IsA(const char* p_name) const override // vtable+0x10
	{
		return !strcmp(p_name, LegoWorld::ClassName()) || LegoEntity::IsA(p_name);
	}

	virtual MxResult Create(MxDSAction& p_dsAction) override; // vtable+0x18
	virtual void Destroy(MxBool p_fromDestructor) override;   // vtable+0x1c
	virtual void VTable0x50();                                // vtable+0x50
	virtual LegoCameraController* VTable0x54();               // vtable+0x54
	virtual void Add(MxCore* p_object);                       // vtable+0x58
	virtual MxBool VTable0x5c();                              // vtable+0x5c

	// FUNCTION: LEGO1 0x100010a0
	virtual void VTable0x60() {} // vtable+0x60

	virtual MxBool VTable0x64();           // vtable+0x64
	virtual void VTable0x68(MxBool p_add); // vtable+0x68

	inline LegoCameraController* GetCamera() { return m_cameraController; }
	inline undefined4 GetUnknown0xec() { return m_unk0xec; }

	undefined FUN_100220e0();
	void Remove(MxCore* p_object);
	void FUN_1001fc80(IslePathActor* p_actor);
	MxBool FUN_100727e0(MxU32, Mx3DPointFloat& p_loc, Mx3DPointFloat& p_dir, Mx3DPointFloat& p_up);
	MxBool FUN_10072980(MxU32, Mx3DPointFloat& p_loc, Mx3DPointFloat& p_dir, Mx3DPointFloat& p_up);
	void FUN_10073400();
	void FUN_10073430();
	MxS32 GetCurrPathInfo(LegoPathBoundary** p_path, MxS32& p_value);
	MxCore* Find(const char* p_class, const char* p_name);
	MxCore* Find(const MxAtomId& p_atom, MxS32 p_entityId);

	// SYNTHETIC: LEGO1 0x1001dee0
	// LegoWorld::`scalar deleting destructor'

protected:
	LegoPathControllerList m_list0x68;          // 0x68
	MxPresenterList m_animPresenters;           // 0x80
	LegoCameraController* m_cameraController;   // 0x98
	LegoEntityList* m_entityList;               // 0x9c
	LegoCacheSoundList* m_cacheSoundList;       // 0xa0
	MxBool m_destroyed;                         // 0xa4
	MxCoreSet m_set0xa8;                        // 0xa8
	MxPresenterList m_controlPresenters;        // 0xb8
	MxCoreSet m_set0xd0;                        // 0xd0
	list<AutoROI*> m_list0xe0;                  // 0xe0
	undefined4 m_unk0xec;                       // 0xec
	LegoHideAnimPresenter* m_hideAnimPresenter; // 0xf0
	MxS16 m_unk0xf4;                            // 0xf4
	MxBool m_worldStarted;                      // 0xf6
	undefined m_unk0xf7;                        // 0xf7
};

// clang-format off
// TEMPLATE: LEGO1 0x1001d780
// _Tree<MxCore *,MxCore *,set<MxCore *,CoreSetCompare,allocator<MxCore *> >::_Kfn,CoreSetCompare,allocator<MxCore *> >::~_Tree<MxCore *,MxCore *,set<MxCore *,CoreSetCompare,allocator<MxCore *> >::_Kfn,CoreSetCompare,allocator<MxCore *> >

// TEMPLATE: LEGO1 0x1001d850
// _Tree<MxCore *,MxCore *,set<MxCore *,CoreSetCompare,allocator<MxCore *> >::_Kfn,CoreSetCompare,allocator<MxCore *> >::iterator::_Inc

// TEMPLATE: LEGO1 0x1001d890
// _Tree<MxCore *,MxCore *,set<MxCore *,CoreSetCompare,allocator<MxCore *> >::_Kfn,CoreSetCompare,allocator<MxCore *> >::erase

// TEMPLATE: LEGO1 0x1001dcf0
// _Tree<MxCore *,MxCore *,set<MxCore *,CoreSetCompare,allocator<MxCore *> >::_Kfn,CoreSetCompare,allocator<MxCore *> >::_Erase

// TEMPLATE: LEGO1 0x1001dd30
// _Tree<MxCore *,MxCore *,set<MxCore *,CoreSetCompare,allocator<MxCore *> >::_Kfn,CoreSetCompare,allocator<MxCore *> >::_Init

// TEMPLATE: LEGO1 0x1001ddf0
// list<AutoROI *,allocator<AutoROI *> >::~list<AutoROI *,allocator<AutoROI *> >

// TEMPLATE: LEGO1 0x1001df50
// List<AutoROI *>::~List<AutoROI *>

// TEMPLATE: LEGO1 0x1001de60
// list<AutoROI *,allocator<AutoROI *> >::_Buynode

// TEMPLATE: LEGO1 0x1001de90
// set<MxCore *,CoreSetCompare,allocator<MxCore *> >::~set<MxCore *,CoreSetCompare,allocator<MxCore *> >

// TEMPLATE: LEGO1 0x1001df00
// Set<MxCore *,CoreSetCompare>::~Set<MxCore *,CoreSetCompare>

// TEMPLATE: LEGO1 0x1001f590
// list<AutoROI *,allocator<AutoROI *> >::erase

// TEMPLATE: LEGO1 0x100208b0
// _Tree<MxCore *,MxCore *,set<MxCore *,CoreSetCompare,allocator<MxCore *> >::_Kfn,CoreSetCompare,allocator<MxCore *> >::insert

// TEMPLATE: LEGO1 0x10020b20
// _Tree<MxCore *,MxCore *,set<MxCore *,CoreSetCompare,allocator<MxCore *> >::_Kfn,CoreSetCompare,allocator<MxCore *> >::iterator::_Dec

// XTEMPLATE LEGO1 0x10020b70

// TEMPLATE: LEGO1 0x10020bb0
// _Tree<MxCore *,MxCore *,set<MxCore *,CoreSetCompare,allocator<MxCore *> >::_Kfn,CoreSetCompare,allocator<MxCore *> >::_Buynode

// TEMPLATE: LEGO1 0x10020bd0
// _Tree<MxCore *,MxCore *,set<MxCore *,CoreSetCompare,allocator<MxCore *> >::_Kfn,CoreSetCompare,allocator<MxCore *> >::_Insert

// TEMPLATE: LEGO1 0x10020e50
// _Tree<MxCore *,MxCore *,set<MxCore *,CoreSetCompare,allocator<MxCore *> >::_Kfn,CoreSetCompare,allocator<MxCore *> >::_Lrotate

// TEMPLATE: LEGO1 0x10020eb0
// _Tree<MxCore *,MxCore *,set<MxCore *,CoreSetCompare,allocator<MxCore *> >::_Kfn,CoreSetCompare,allocator<MxCore *> >::_Rrotate

// TEMPLATE: LEGO1 0x10021340
// _Tree<MxCore *,MxCore *,set<MxCore *,CoreSetCompare,allocator<MxCore *> >::_Kfn,CoreSetCompare,allocator<MxCore *> >::find

// TEMPLATE: LEGO1 0x10022360
// _Construct

// GLOBAL: LEGO1 0x100f11a0
// _Tree<MxCore *,MxCore *,set<MxCore *,CoreSetCompare,allocator<MxCore *> >::_Kfn,CoreSetCompare,allocator<MxCore *> >::_Nil
// clang-format on

#endif // LEGOWORLD_H
