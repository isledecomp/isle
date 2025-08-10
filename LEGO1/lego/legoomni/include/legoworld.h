#ifndef LEGOWORLD_H
#define LEGOWORLD_H

// clang-format off
#include "mxpresenterlist.h"
#include "legoentitylist.h"
#include "legocachesoundlist.h"
// clang-format on

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
	virtual MxBool EnabledAfterDestruction() { return FALSE; } // vtable+0x5c

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
	list<LegoROI*>& GetROIList() { return m_roiList; }
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
// list<LegoROI *,allocator<LegoROI *> >::~list<LegoROI *,allocator<LegoROI *> >

// TEMPLATE: LEGO1 0x1001df50
// List<LegoROI *>::~List<LegoROI *>

// TEMPLATE: LEGO1 0x1001de60
// list<LegoROI *,allocator<LegoROI *> >::_Buynode

// TEMPLATE: LEGO1 0x1001de90
// set<MxCore *,CoreSetCompare,allocator<MxCore *> >::~set<MxCore *,CoreSetCompare,allocator<MxCore *> >

// TEMPLATE: LEGO1 0x1001df00
// Set<MxCore *,CoreSetCompare>::~Set<MxCore *,CoreSetCompare>

// TEMPLATE: LEGO1 0x1001f590
// list<LegoROI *,allocator<LegoROI *> >::erase

// TEMPLATE: LEGO1 0x100208b0
// _Tree<MxCore *,MxCore *,set<MxCore *,CoreSetCompare,allocator<MxCore *> >::_Kfn,CoreSetCompare,allocator<MxCore *> >::insert

// TEMPLATE: LEGO1 0x10020b20
// _Tree<MxCore *,MxCore *,set<MxCore *,CoreSetCompare,allocator<MxCore *> >::_Kfn,CoreSetCompare,allocator<MxCore *> >::iterator::_Dec

// TEMPLATE: LEGO1 0x10020b70
// _Tree<MxCore *,MxCore *,set<MxCore *,CoreSetCompare,allocator<MxCore *> >::_Kfn,CoreSetCompare,allocator<MxCore *> >::lower_bound

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
// ?_Construct@@YAXPAPAVMxCore@@ABQAV1@@Z

// GLOBAL: LEGO1 0x100f11a0
// _Tree<MxCore *,MxCore *,set<MxCore *,CoreSetCompare,allocator<MxCore *> >::_Kfn,CoreSetCompare,allocator<MxCore *> >::_Nil
// clang-format on

#endif // LEGOWORLD_H
