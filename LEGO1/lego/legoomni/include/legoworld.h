#ifndef LEGOWORLD_H
#define LEGOWORLD_H

#include "legocameracontroller.h"
#include "legoentity.h"
#include "legoentitylist.h"
#include "legopathcontrollerlist.h"
#include "mxcorelist.h"
#include "mxpresenter.h"
#include "mxpresenterlist.h"

class IslePathActor;
class LegoPathBoundary;

struct PresenterSetCompare {
	MxS32 operator()(MxPresenter* const& p_a, MxPresenter* const& p_b) const { return p_a > p_b; }
};

typedef set<MxPresenter*, PresenterSetCompare> MxPresenterSet;

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
	virtual void VTable0x58(MxCore* p_object);                // vtable+0x58
	virtual MxBool VTable0x5c();                              // vtable+0x5c

	// FUNCTION: LEGO1 0x100010a0
	virtual void VTable0x60() {} // vtable+0x60

	virtual MxBool VTable0x64();           // vtable+0x64
	virtual void VTable0x68(MxBool p_add); // vtable+0x68

	inline LegoCameraController* GetCamera() { return m_cameraController; }
	inline undefined4 GetUnknown0xec() { return m_unk0xec; }

	undefined FUN_100220e0();
	void EndAction(MxCore* p_object);
	void FUN_1001fc80(IslePathActor* p_actor);
	MxBool FUN_100727e0(MxU32, Mx3DPointFloat& p_loc, Mx3DPointFloat& p_dir, Mx3DPointFloat& p_up);
	MxBool FUN_10072980(MxU32, Mx3DPointFloat& p_loc, Mx3DPointFloat& p_dir, Mx3DPointFloat& p_up);
	void FUN_10073400();
	void FUN_10073430();
	MxS32 GetCurrPathInfo(LegoPathBoundary** p_path, MxS32& p_value);
	MxCore* FUN_100213a0(const char* p_class, const char* p_name);
	MxCore* FUN_10021790(const MxAtomId& p_atom, MxS32 p_entityId);

	// SYNTHETIC: LEGO1 0x1001dee0
	// LegoWorld::`scalar deleting destructor'

protected:
	LegoPathControllerList m_list0x68;        // 0x68
	MxPresenterList m_animPresenters;         // 0x80
	LegoCameraController* m_cameraController; // 0x98
	LegoEntityList* m_entityList;             // 0x9c
	MxCoreList* m_coreList;                   // 0xa0
	undefined m_unk0xa4;                      // 0xa4
	MxPresenterSet m_set0xa8;                 // 0xa8
	MxPresenterList m_controlPresenters;      // 0xb8
	MxPresenterSet m_set0xd0;                 // 0xd0
	list<AutoROI*> m_list0xe0;                // 0xe0
	undefined4 m_unk0xec;                     // 0xec
	undefined4 m_unk0xf0;                     // 0xf0
	MxS16 m_unk0xf4;                          // 0xf4
	MxBool m_worldStarted;                    // 0xf6
	undefined m_unk0xf7;                      // 0xf7
};

// clang-format off
// TEMPLATE: LEGO1 0x1001d780
// _Tree<MxPresenter *,MxPresenter *,set<MxPresenter *,PresenterSetCompare,allocator<MxPresenter *> >::_Kfn,PresenterSetCompare,allocator<MxPresenter *> >::~_Tree<MxPresenter *,MxPresenter *,set<MxPresenter *,PresenterSetCompare,allocator<MxPresenter *> >::_Kfn,PresenterSetCompare,allocator<MxPresenter *> >

// TEMPLATE: LEGO1 0x1001d850
// _Tree<MxPresenter *,MxPresenter *,set<MxPresenter *,PresenterSetCompare,allocator<MxPresenter *> >::_Kfn,PresenterSetCompare,allocator<MxPresenter *> >::iterator::_Inc

// TEMPLATE: LEGO1 0x1001d890
// _Tree<MxPresenter *,MxPresenter *,set<MxPresenter *,PresenterSetCompare,allocator<MxPresenter *> >::_Kfn,PresenterSetCompare,allocator<MxPresenter *> >::erase

// TEMPLATE: LEGO1 0x1001dcf0
// _Tree<MxPresenter *,MxPresenter *,set<MxPresenter *,PresenterSetCompare,allocator<MxPresenter *> >::_Kfn,PresenterSetCompare,allocator<MxPresenter *> >::_Erase

// TEMPLATE: LEGO1 0x1001dd30
// _Tree<MxPresenter *,MxPresenter *,set<MxPresenter *,PresenterSetCompare,allocator<MxPresenter *> >::_Kfn,PresenterSetCompare,allocator<MxPresenter *> >::_Init

// TEMPLATE: LEGO1 0x1001ddf0
// list<AutoROI *,allocator<AutoROI *> >::~list<AutoROI *,allocator<AutoROI *> >

// TEMPLATE: LEGO1 0x1001df50
// List<AutoROI *>::~List<AutoROI *>

// TEMPLATE: LEGO1 0x1001de60
// list<AutoROI *,allocator<AutoROI *> >::_Buynode

// TEMPLATE: LEGO1 0x1001de90
// set<MxPresenter *,PresenterSetCompare,allocator<MxPresenter *> >::~set<MxPresenter *,PresenterSetCompare,allocator<MxPresenter *> >

// TEMPLATE: LEGO1 0x1001df00
// Set<MxPresenter *,PresenterSetCompare>::~Set<MxPresenter *,PresenterSetCompare>

// SYNTHETIC: LEGO1 0x1001eed0
// MxPresenterListCursor::`scalar deleting destructor'

// TEMPLATE: LEGO1 0x1001ef40
// MxPtrListCursor<MxPresenter>::~MxPtrListCursor<MxPresenter>

// SYNTHETIC: LEGO1 0x1001ef90
// MxListCursor<MxPresenter *>::`scalar deleting destructor'

// SYNTHETIC: LEGO1 0x1001f000
// MxPtrListCursor<MxPresenter>::`scalar deleting destructor'

// TEMPLATE: LEGO1 0x1001f070
// MxListCursor<MxPresenter *>::~MxListCursor<MxPresenter *>

// FUNCTION: LEGO1 0x1001f0c0
// MxPresenterListCursor::~MxPresenterListCursor

// TEMPLATE: LEGO1 0x10020760
// MxListCursor<MxPresenter *>::MxListCursor<MxPresenter *>

// GLOBAL: LEGO1 0x100f11a0
// _Tree<MxPresenter *,MxPresenter *,set<MxPresenter *,PresenterSetCompare,allocator<MxPresenter *>>::_Kfn,PresenterSetCompare,allocator<MxPresenter *> >::_Nil
// clang-format on

#endif // LEGOWORLD_H
