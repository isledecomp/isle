#ifndef LEGOWORLD_H
#define LEGOWORLD_H

#include "mxpresenterlist.h"
#include "legoentitylist.h"
#include "legocachesoundlist.h"

#include "legoentity.h"
#include "legomain.h"
#include "legopathcontrollerlist.h"
#include "roi/legoroi.h"

class LegoCameraController;
class LegoPathBoundary;
class LegoHideAnimPresenter;

#if defined(_M_IX86) || defined(__i386__)
#define COMPARE_POINTER_TYPE MxS32
#else
#define COMPARE_POINTER_TYPE MxS32*
#endif

struct CoreSetCompare {
	MxS32 operator()(MxCore* const& p_a, MxCore* const& p_b) const
	{
		return (COMPARE_POINTER_TYPE) p_a < (COMPARE_POINTER_TYPE) p_b;
	}
};

typedef set<MxCore*, CoreSetCompare> MxCoreSet;

// VTABLE: LEGO1 0x100d6280
// VTABLE: BETA10 0x101befd8
// SIZE 0xf8
class LegoWorld : public LegoEntity {
public:
	enum StartupTicks {
		e_start = 0,
		e_one,
		e_two,
		e_three,
		e_four
	};

	LegoWorld();
	~LegoWorld() override; // vtable+0x00

	MxLong Notify(MxParam& p_param) override;                   // vtable+0x04
	MxResult Tickle() override;                                 // vtable+0x08
	MxResult Create(MxDSAction& p_dsAction) override;           // vtable+0x18
	void Destroy(MxBool p_fromDestructor) override;             // vtable+0x1c
	virtual void ReadyWorld();                                  // vtable+0x50
	virtual LegoCameraController* InitializeCameraController(); // vtable+0x54
	virtual void Add(MxCore* p_object);                         // vtable+0x58

	// The BETA10 match could also be LegoWorld::Escape(), only the child classes might be able to tell
	// FUNCTION: LEGO1 0x1001d670
	// FUNCTION: BETA10 0x10017530
	virtual MxBool WaitForTransition() { return FALSE; } // vtable+0x5c

	// FUNCTION: LEGO1 0x100010a0
	virtual void VTable0x60() {} // vtable+0x60

	// FUNCTION: LEGO1 0x1001d680
	virtual MxBool Escape() { return FALSE; } // vtable+0x64

	virtual void Enable(MxBool p_enable); // vtable+0x68

	// FUNCTION: LEGO1 0x1001d690
	// FUNCTION: BETA10 0x10017660
	const char* ClassName() const override // vtable+0x0c
	{
		// STRING: LEGO1 0x100f0058
		return "LegoWorld";
	}

	// FUNCTION: LEGO1 0x1001d6a0
	// FUNCTION: BETA10 0x100175f0
	MxBool IsA(const char* p_name) const override // vtable+0x10
	{
		return !strcmp(p_name, LegoWorld::ClassName()) || LegoEntity::IsA(p_name);
	}

	MxBool PresentersPending();
	void Remove(MxCore* p_object);
	MxResult PlaceActor(
		LegoPathActor* p_actor,
		const char* p_name,
		MxS32 p_src,
		float p_srcScale,
		MxS32 p_dest,
		float p_destScale
	);
	MxResult PlaceActor(LegoPathActor* p_actor);
	MxResult PlaceActor(
		LegoPathActor* p_actor,
		LegoAnimPresenter* p_presenter,
		Vector3& p_position,
		Vector3& p_direction
	);
	void RemoveActor(LegoPathActor* p_actor);
	MxBool ActorExists(LegoPathActor* p_actor);
	void AddPresenterIfInRange(LegoAnimPresenter* p_presenter);
	void RemovePresenterFromBoundaries(LegoAnimPresenter* p_presenter);
	LegoPathBoundary* FindPathBoundary(const char* p_name);
	void AddPath(LegoPathController* p_controller);
	MxResult GetCurrPathInfo(LegoPathBoundary** p_boundaries, MxS32& p_numL);
	MxCore* Find(const char* p_class, const char* p_name);
	MxCore* Find(const MxAtomId& p_atom, MxS32 p_entityId);

	// FUNCTION: BETA10 0x1002b4f0
	LegoCameraController* GetCameraController() { return m_cameraController; }

	LegoEntityList* GetEntityList() { return m_entityList; }
	LegoOmni::World GetWorldId() { return m_worldId; }
	MxBool NoDisabledObjects() { return m_disabledObjects.empty(); }
	list<LegoROI*>* GetROIList() { return &m_roiList; }
	LegoHideAnimPresenter* GetHideAnimPresenter() { return m_hideAnim; }

	void SetWorldId(LegoOmni::World p_worldId) { m_worldId = p_worldId; }

	// SYNTHETIC: LEGO1 0x1001dee0
	// LegoWorld::`scalar deleting destructor'

protected:
	LegoPathControllerList m_pathControllerList; // 0x68
	MxPresenterList m_animPresenters;            // 0x80
	LegoCameraController* m_cameraController;    // 0x98
	LegoEntityList* m_entityList;                // 0x9c
	LegoCacheSoundList* m_cacheSoundList;        // 0xa0
	MxBool m_destroyed;                          // 0xa4
	MxCoreSet m_objects;                         // 0xa8
	MxPresenterList m_controlPresenters;         // 0xb8
	MxCoreSet m_disabledObjects;                 // 0xd0
	list<LegoROI*> m_roiList;                    // 0xe0
	LegoOmni::World m_worldId;                   // 0xec

	// name verified by BETA10 0x100c7f59
	LegoHideAnimPresenter* m_hideAnim; // 0xf0

	MxS16 m_startupTicks;  // 0xf4
	MxBool m_worldStarted; // 0xf6
	undefined m_unk0xf7;   // 0xf7
};

// clang-format off
// TEMPLATE: LEGO1 0x1001d780 SYMBOL
// ??1?$_Tree@PAVMxCore@@PAV1@U_Kfn@?$set@PAVMxCore@@UCoreSetCompare@@V?$allocator@PAVMxCore@@@@@@UCoreSetCompare@@V?$allocator@PAVMxCore@@@@@@QAE@XZ

// TEMPLATE: LEGO1 0x1001d850 SYMBOL
// ?_Inc@iterator@?$_Tree@PAVMxCore@@PAV1@U_Kfn@?$set@PAVMxCore@@UCoreSetCompare@@V?$allocator@PAVMxCore@@@@@@UCoreSetCompare@@V?$allocator@PAVMxCore@@@@@@QAEXXZ

// TEMPLATE: LEGO1 0x1001d890 SYMBOL
// ?erase@?$_Tree@PAVMxCore@@PAV1@U_Kfn@?$set@PAVMxCore@@UCoreSetCompare@@V?$allocator@PAVMxCore@@@@@@UCoreSetCompare@@V?$allocator@PAVMxCore@@@@@@QAE?AViterator@1@V21@@Z

// TEMPLATE: LEGO1 0x1001dcf0 SYMBOL
// ?_Erase@?$_Tree@PAVMxCore@@PAV1@U_Kfn@?$set@PAVMxCore@@UCoreSetCompare@@V?$allocator@PAVMxCore@@@@@@UCoreSetCompare@@V?$allocator@PAVMxCore@@@@@@IAEXPAU_Node@1@@Z

// TEMPLATE: LEGO1 0x1001dd30 SYMBOL
// ?_Init@?$_Tree@PAVMxCore@@PAV1@U_Kfn@?$set@PAVMxCore@@UCoreSetCompare@@V?$allocator@PAVMxCore@@@@@@UCoreSetCompare@@V?$allocator@PAVMxCore@@@@@@IAEXXZ

// TEMPLATE: LEGO1 0x1001ddf0 SYMBOL
// ??1?$list@PAVLegoROI@@V?$allocator@PAVLegoROI@@@@@@QAE@XZ

// TEMPLATE: LEGO1 0x1001df50
// List<LegoROI *>::~List<LegoROI *>

// TEMPLATE: LEGO1 0x1001de60 SYMBOL
// ?_Buynode@?$list@PAVLegoROI@@V?$allocator@PAVLegoROI@@@@@@IAEPAU_Node@1@PAU21@0@Z

// TEMPLATE: LEGO1 0x1001de90 SYMBOL
// ??1?$set@PAVMxCore@@UCoreSetCompare@@V?$allocator@PAVMxCore@@@@@@QAE@XZ

// TEMPLATE: LEGO1 0x1001df00
// Set<MxCore *,CoreSetCompare>::~Set<MxCore *,CoreSetCompare>

// TEMPLATE: LEGO1 0x1001f590 SYMBOL
// ?erase@?$list@PAVLegoROI@@V?$allocator@PAVLegoROI@@@@@@QAE?AViterator@1@V21@@Z

// TEMPLATE: LEGO1 0x100208b0 SYMBOL
// ?insert@?$_Tree@PAVMxCore@@PAV1@U_Kfn@?$set@PAVMxCore@@UCoreSetCompare@@V?$allocator@PAVMxCore@@@@@@UCoreSetCompare@@V?$allocator@PAVMxCore@@@@@@QAE?AU?$pair@Viterator@?$_Tree@PAVMxCore@@PAV1@U_Kfn@?$set@PAVMxCore@@UCoreSetCompare@@V?$allocator@PAVMxCore@

// TEMPLATE: LEGO1 0x10020b20 SYMBOL
// ?_Dec@iterator@?$_Tree@PAVMxCore@@PAV1@U_Kfn@?$set@PAVMxCore@@UCoreSetCompare@@V?$allocator@PAVMxCore@@@@@@UCoreSetCompare@@V?$allocator@PAVMxCore@@@@@@QAEXXZ

// TEMPLATE: LEGO1 0x10020b70 SYMBOL
// ?lower_bound@?$_Tree@PAVMxCore@@PAV1@U_Kfn@?$set@PAVMxCore@@UCoreSetCompare@@V?$allocator@PAVMxCore@@@@@@UCoreSetCompare@@V?$allocator@PAVMxCore@@@@@@QBE?AVconst_iterator@1@ABQAVMxCore@@@Z

// TEMPLATE: LEGO1 0x10020bb0 SYMBOL
// ?_Buynode@?$_Tree@PAVMxCore@@PAV1@U_Kfn@?$set@PAVMxCore@@UCoreSetCompare@@V?$allocator@PAVMxCore@@@@@@UCoreSetCompare@@V?$allocator@PAVMxCore@@@@@@IAEPAU_Node@1@PAU21@W4_Redbl@1@@Z

// TEMPLATE: LEGO1 0x10020bd0 SYMBOL
// ?_Insert@?$_Tree@PAVMxCore@@PAV1@U_Kfn@?$set@PAVMxCore@@UCoreSetCompare@@V?$allocator@PAVMxCore@@@@@@UCoreSetCompare@@V?$allocator@PAVMxCore@@@@@@IAE?AViterator@1@PAU_Node@1@0ABQAVMxCore@@@Z

// TEMPLATE: LEGO1 0x10020e50 SYMBOL
// ?_Lrotate@?$_Tree@PAVMxCore@@PAV1@U_Kfn@?$set@PAVMxCore@@UCoreSetCompare@@V?$allocator@PAVMxCore@@@@@@UCoreSetCompare@@V?$allocator@PAVMxCore@@@@@@IAEXPAU_Node@1@@Z

// TEMPLATE: LEGO1 0x10020eb0 SYMBOL
// ?_Rrotate@?$_Tree@PAVMxCore@@PAV1@U_Kfn@?$set@PAVMxCore@@UCoreSetCompare@@V?$allocator@PAVMxCore@@@@@@UCoreSetCompare@@V?$allocator@PAVMxCore@@@@@@IAEXPAU_Node@1@@Z

// TEMPLATE: LEGO1 0x10021340 SYMBOL
// ?find@?$_Tree@PAVMxCore@@PAV1@U_Kfn@?$set@PAVMxCore@@UCoreSetCompare@@V?$allocator@PAVMxCore@@@@@@UCoreSetCompare@@V?$allocator@PAVMxCore@@@@@@QBE?AVconst_iterator@1@ABQAVMxCore@@@Z

// TEMPLATE: LEGO1 0x10022360
// ?_Construct@@YAXPAPAVMxCore@@ABQAV1@@Z

// GLOBAL: LEGO1 0x100f11a0
// _Tree<MxCore *,MxCore *,set<MxCore *,CoreSetCompare,allocator<MxCore *> >::_Kfn,CoreSetCompare,allocator<MxCore *> >::_Nil
// clang-format on

#endif // LEGOWORLD_H
