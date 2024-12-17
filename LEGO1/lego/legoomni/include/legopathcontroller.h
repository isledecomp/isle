#ifndef LEGOPATHCONTROLLER_H
#define LEGOPATHCONTROLLER_H

#include "decomp.h"
#include "geom/legounkown100db7f4.h"
#include "legopathactor.h"
#include "legopathboundary.h"
#include "mxcore.h"
#include "mxstl/stlcompat.h"

class LegoAnimPresenter;
class LegoPathStruct;
class LegoWorld;
class MxAtomId;
class Vector3;

#if defined(_M_IX86) || defined(__i386__)
#define COMPARE_POINTER_TYPE MxS32
#else
#define COMPARE_POINTER_TYPE MxS32*
#endif

// VTABLE: LEGO1 0x100d7da8
// SIZE 0x40
struct LegoPathCtrlEdge : public LegoUnknown100db7f4 {};

struct LegoPathCtrlEdgeCompare {
	MxU32 operator()(const LegoPathCtrlEdge* p_lhs, const LegoPathCtrlEdge* p_rhs) const
	{
		return (COMPARE_POINTER_TYPE) p_lhs < (COMPARE_POINTER_TYPE) p_rhs;
	}
};

typedef set<LegoPathCtrlEdge*, LegoPathCtrlEdgeCompare> LegoPathCtrlEdgeSet;

// VTABLE: LEGO1 0x100d7d60
// SIZE 0x40
class LegoPathController : public MxCore {
public:
	// SIZE 0x08
	struct CtrlBoundary {
		// FUNCTION: LEGO1 0x10046dc0
		CtrlBoundary()
		{
			m_controller = NULL;
			m_boundary = NULL;
		}

		LegoPathController* m_controller; // 0x00
		LegoPathBoundary* m_boundary;     // 0x04
	};

	// SIZE 0x08
	struct CtrlEdge {
		// FUNCTION: LEGO1 0x10046dd0
		CtrlEdge()
		{
			m_controller = NULL;
			m_edge = NULL;
		}

		LegoPathController* m_controller; // 0x00
		LegoUnknown100db7f4* m_edge;      // 0x04
	};

	LegoPathController();
	~LegoPathController() override { Destroy(); }

	MxResult Tickle() override; // vtable+08

	// FUNCTION: LEGO1 0x10045110
	const char* ClassName() const override // vtable+0x0c
	{
		// STRING: LEGO1 0x100f11b8
		return "LegoPathController";
	}

	// FUNCTION: LEGO1 0x10045120
	MxBool IsA(const char* p_name) const override // vtable+0x10
	{
		return !strcmp(p_name, LegoPathController::ClassName()) || MxCore::IsA(p_name);
	}

	// SYNTHETIC: LEGO1 0x10045740
	// LegoPathController::`scalar deleting destructor'

	virtual MxResult Create(MxU8* p_data, const Vector3& p_location, const MxAtomId& p_trigger); // vtable+0x14
	virtual void Destroy();                                                                      // vtable+0x18

	MxResult PlaceActor(
		LegoPathActor* p_actor,
		const char* p_name,
		MxS32 p_src,
		float p_srcScale,
		MxS32 p_dest,
		float p_destScale
	);
	MxResult PlaceActor(
		LegoPathActor* p_actor,
		LegoAnimPresenter* p_presenter,
		Vector3& p_position,
		Vector3& p_direction
	);
	MxResult PlaceActor(LegoPathActor* p_actor);
	MxResult RemoveActor(LegoPathActor* p_actor);
	void FUN_100468f0(LegoAnimPresenter* p_presenter);
	void FUN_10046930(LegoAnimPresenter* p_presenter);
	MxResult FUN_10046b30(LegoPathBoundary*& p_boundaries, MxS32& p_numL);
	LegoPathBoundary* GetPathBoundary(const char* p_name);
	void Enable(MxBool p_enable);
	void FUN_10046bb0(LegoWorld* p_world);
	MxResult FUN_10048310(
		LegoPathEdgeContainer* p_grec,
		const Vector3& p_oldPosition,
		const Vector3& p_oldDirection,
		LegoPathBoundary* p_oldBoundary,
		const Vector3& p_newPosition,
		const Vector3& p_newDirection,
		LegoPathBoundary* p_newBoundary,
		LegoU8 p_mask,
		MxFloat* p_param9
	);
	MxS32 FUN_1004a240(
		LegoPathEdgeContainer& p_grec,
		Vector3& p_v1,
		Vector3& p_v2,
		float p_f1,
		LegoUnknown100db7f4*& p_edge,
		LegoPathBoundary*& p_boundary
	);
	MxResult FUN_1004a380(
		Vector3& p_param1,
		Vector3& p_param2,
		Mx3DPointFloat* p_param3,
		LegoPathBoundary*& p_boundary,
		MxFloat& p_param5
	);

	static MxResult Init();
	static MxResult Reset();

	// FUNCTION: BETA10 0x100cf580
	static LegoUnknown100db7f4* GetControlEdgeA(MxS32 p_index) { return g_ctrlEdgesA[p_index].m_edge; }

	// FUNCTION: BETA10 0x100cf5b0
	static LegoPathBoundary* GetControlBoundaryA(MxS32 p_index) { return g_ctrlBoundariesA[p_index].m_boundary; }

	// These two are an educated guess because BETA10 does not have the g_ctrl.*B globals
	static LegoUnknown100db7f4* GetControlEdgeB(MxS32 p_index) { return g_ctrlEdgesB[p_index].m_edge; }
	static LegoPathBoundary* GetControlBoundaryB(MxS32 p_index) { return g_ctrlBoundariesB[p_index].m_boundary; }

private:
	void FUN_10046970();
	MxResult Read(LegoStorage* p_storage);
	MxResult ReadStructs(LegoStorage* p_storage);
	MxResult ReadEdges(LegoStorage* p_storage);
	MxResult ReadBoundaries(LegoStorage* p_storage);
	static MxResult ReadVector(LegoStorage* p_storage, Mx3DPointFloat& p_vec);
	static MxResult ReadVector(LegoStorage* p_storage, Mx4DPointFloat& p_vec);

	// FUNCTION: BETA10 0x100c16f0
	static MxU32 IsBetween(MxFloat p_v, MxFloat p_a, MxFloat p_b)
	{
		if (p_a <= p_b) {
			return p_v >= p_a && p_v <= p_b;
		}
		else {
			return p_v <= p_a && p_v >= p_b;
		}
	}

	// FUNCTION: BETA10 0x100c17a0
	static MxU32 FUN_100c17a0(MxFloat p_v1, MxFloat p_v2, MxFloat p_a, MxFloat p_b)
	{
		assert(IsBetween(p_v1, p_a, p_b));
		assert(IsBetween(p_v2, p_a, p_b));

		if (p_a <= p_b) {
			return p_v1 < p_v2;
		}
		else {
			return p_v1 > p_v2;
		}
	}

	LegoPathBoundary* m_boundaries; // 0x08
	LegoPathCtrlEdge* m_edges;      // 0x0c
	Mx3DPointFloat* m_unk0x10;      // 0x10
	LegoPathStruct* m_structs;      // 0x14
	MxU16 m_numL;                   // 0x18
	MxU16 m_numE;                   // 0x1a
	MxU16 m_numN;                   // 0x1c
	MxU16 m_numT;                   // 0x1e
	LegoPathCtrlEdgeSet m_pfsE;     // 0x20
	LegoPathActorSet m_actors;      // 0x30

	// Names verified by BETA10
	static CtrlBoundary* g_ctrlBoundariesA;
	static CtrlEdge* g_ctrlEdgesA;

	static const char* g_unk0x100f42f0[];
	static const char* g_unk0x100f4330[];
	static CtrlBoundary* g_ctrlBoundariesB;
	static CtrlEdge* g_ctrlEdgesB;
};

// clang-format off
// TEMPLATE: LEGO1 0x1001fd70
// _Tree<LegoPathActor *,LegoPathActor *,set<LegoPathActor *,LegoPathActorSetCompare,allocator<LegoPathActor *> >::_Kfn,LegoPathActorSetCompare,allocator<LegoPathActor *> >::_Lbound

// TEMPLATE: LEGO1 0x1002c4a0
// _Tree<LegoPathActor *,LegoPathActor *,set<LegoPathActor *,LegoPathActorSetCompare,allocator<LegoPathActor *> >::_Kfn,LegoPathActorSetCompare,allocator<LegoPathActor *> >::_Buynode

// TEMPLATE: LEGO1 0x100451a0
// _Tree<LegoPathCtrlEdge *,LegoPathCtrlEdge *,set<LegoPathCtrlEdge *,LegoPathCtrlEdgeCompare,allocator<LegoPathCtrlEdge *> >::_Kfn,LegoPathCtrlEdgeCompare,allocator<LegoPathCtrlEdge *> >::~_Tree<LegoPathCtrlEdge *,LegoPathCtrlEdge *,set<LegoPathCtrlEdge *,LegoPathControl

// TEMPLATE: LEGO1 0x10045270
// _Tree<LegoPathCtrlEdge *,LegoPathCtrlEdge *,set<LegoPathCtrlEdge *,LegoPathCtrlEdgeCompare,allocator<LegoPathCtrlEdge *> >::_Kfn,LegoPathCtrlEdgeCompare,allocator<LegoPathCtrlEdge *> >::iterator::_Inc

// TEMPLATE: LEGO1 0x100452b0
// ?erase@?$_Tree@PAULegoPathCtrlEdge@@PAU1@U_Kfn@?$set@PAULegoPathCtrlEdge@@ULegoPathCtrlEdgeCompare@@V?$allocator@PAULegoPathCtrlEdge@@@@@@ULegoPathCtrlEdgeCompare@@V?$allocator@PAULegoPathCtrlEdge@@@@@@QAE?AViterator@1@V21@@Z

// TEMPLATE: LEGO1 0x10045700
// _Tree<LegoPathCtrlEdge *,LegoPathCtrlEdge *,set<LegoPathCtrlEdge *,LegoPathCtrlEdgeCompare,allocator<LegoPathCtrlEdge *> >::_Kfn,LegoPathCtrlEdgeCompare,allocator<LegoPathCtrlEdge *> >::_Erase

// TEMPLATE: LEGO1 0x100457e0
// Set<LegoPathCtrlEdge *,LegoPathCtrlEdgeCompare>::~Set<LegoPathCtrlEdge *,LegoPathCtrlEdgeCompare>

// TEMPLATE: LEGO1 0x10045830
// set<LegoPathCtrlEdge *,LegoPathCtrlEdgeCompare,allocator<LegoPathCtrlEdge *> >::~set<LegoPathCtrlEdge *,LegoPathCtrlEdgeCompare,allocator<LegoPathCtrlEdge *> >

// TEMPLATE: LEGO1 0x10046640
// _Tree<LegoAnimPresenter *,LegoAnimPresenter *,set<LegoAnimPresenter *,LegoAnimPresenterSetCompare,allocator<LegoAnimPresenter *> >::_Kfn,LegoAnimPresenterSetCompare,allocator<LegoAnimPresenter *> >::find

// TEMPLATE: LEGO1 0x100468c0
// _Tree<LegoPathActor *,LegoPathActor *,set<LegoPathActor *,LegoPathActorSetCompare,allocator<LegoPathActor *> >::_Kfn,LegoPathActorSetCompare,allocator<LegoPathActor *> >::_Ubound

// TEMPLATE: LEGO1 0x10047550
// _Tree<LegoPathCtrlEdge *,LegoPathCtrlEdge *,set<LegoPathCtrlEdge *,LegoPathCtrlEdgeCompare,allocator<LegoPathCtrlEdge *> >::_Kfn,LegoPathCtrlEdgeCompare,allocator<LegoPathCtrlEdge *> >::_Insert

// TEMPLATE: LEGO1 0x100474e0
// _Tree<LegoPathCtrlEdge *,LegoPathCtrlEdge *,set<LegoPathCtrlEdge *,LegoPathCtrlEdgeCompare,allocator<LegoPathCtrlEdge *> >::_Kfn,LegoPathCtrlEdgeCompare,allocator<LegoPathCtrlEdge *> >::iterator::_Dec

// TEMPLATE: LEGO1 0x10047530
// _Tree<LegoPathCtrlEdge *,LegoPathCtrlEdge *,set<LegoPathCtrlEdge *,LegoPathCtrlEdgeCompare,allocator<LegoPathCtrlEdge *> >::_Kfn,LegoPathCtrlEdgeCompare,allocator<LegoPathCtrlEdge *> >::_Buynode

// TEMPLATE: LEGO1 0x100477d0
// _Tree<LegoPathCtrlEdge *,LegoPathCtrlEdge *,set<LegoPathCtrlEdge *,LegoPathCtrlEdgeCompare,allocator<LegoPathCtrlEdge *> >::_Kfn,LegoPathCtrlEdgeCompare,allocator<LegoPathCtrlEdge *> >::_Lrotate

// TEMPLATE: LEGO1 0x10047830
// _Tree<LegoPathCtrlEdge *,LegoPathCtrlEdge *,set<LegoPathCtrlEdge *,LegoPathCtrlEdgeCompare,allocator<LegoPathCtrlEdge *> >::_Kfn,LegoPathCtrlEdgeCompare,allocator<LegoPathCtrlEdge *> >::_Rrotate

// SYNTHETIC: LEGO1 0x10047940
// LegoPathCtrlEdge::`vector deleting destructor'

// SYNTHETIC: LEGO1 0x100479d0
// LegoPathCtrlEdge::LegoPathCtrlEdge

// SYNTHETIC: LEGO1 0x10047a30
// LegoPathCtrlEdge::~LegoPathCtrlEdge

// SYNTHETIC: LEGO1 0x10047ae0
// LegoUnknown100db7f4::~LegoUnknown100db7f4

// TEMPLATE: LEGO1 0x10048f00
// list<LegoBoundaryEdge,allocator<LegoBoundaryEdge> >::begin

// TEMPLATE: LEGO1 0x10048f10
// list<LegoBoundaryEdge,allocator<LegoBoundaryEdge> >::insert

// TEMPLATE: LEGO1 0x10048f70
// list<LegoBoundaryEdge,allocator<LegoBoundaryEdge> >::erase

// TEMPLATE: LEGO1 0x10048fc0
// _Tree<LegoPathCtrlEdge *,LegoPathCtrlEdge *,set<LegoPathCtrlEdge *,LegoPathCtrlEdgeCompare,allocator<LegoPathCtrlEdge *> >::_Kfn,LegoPathCtrlEdgeCompare,allocator<LegoPathCtrlEdge *> >::_Tree<LegoPathCtrlEdge *,LegoPathCtrlEdge *,set<LegoPathCtrlEdge *,Le

// TEMPLATE: LEGO1 0x10049160
// ?erase@?$_Tree@PAULegoPathCtrlEdge@@PAU1@U_Kfn@?$set@PAULegoPathCtrlEdge@@ULegoPathCtrlEdgeCompare@@V?$allocator@PAULegoPathCtrlEdge@@@@@@ULegoPathCtrlEdgeCompare@@V?$allocator@PAULegoPathCtrlEdge@@@@@@QAEIABQAULegoPathCtrlEdge@@@Z

// TEMPLATE: LEGO1 0x10049290
// _Tree<LegoPathCtrlEdge *,LegoPathCtrlEdge *,set<LegoPathCtrlEdge *,LegoPathCtrlEdgeCompare,allocator<LegoPathCtrlEdge *> >::_Kfn,LegoPathCtrlEdgeCompare,allocator<LegoPathCtrlEdge *> >::find

// TEMPLATE: LEGO1 0x100492f0
// _Tree<LegoPathCtrlEdge *,LegoPathCtrlEdge *,set<LegoPathCtrlEdge *,LegoPathCtrlEdgeCompare,allocator<LegoPathCtrlEdge *> >::_Kfn,LegoPathCtrlEdgeCompare,allocator<LegoPathCtrlEdge *> >::_Copy

// TEMPLATE: LEGO1 0x10049370
// _Tree<LegoPathCtrlEdge *,LegoPathCtrlEdge *,set<LegoPathCtrlEdge *,LegoPathCtrlEdgeCompare,allocator<LegoPathCtrlEdge *> >::_Kfn,LegoPathCtrlEdgeCompare,allocator<LegoPathCtrlEdge *> >::_Ubound

// TEMPLATE: LEGO1 0x100493a0
// list<LegoBEWithFloat,allocator<LegoBEWithFloat> >::~list<LegoBEWithFloat,allocator<LegoBEWithFloat> >

// TEMPLATE: LEGO1 0x10049410
// list<LegoBEWithFloat,allocator<LegoBEWithFloat> >::insert

// TEMPLATE: LEGO1 0x10049470
// list<LegoBEWithFloat,allocator<LegoBEWithFloat> >::_Buynode

// TEMPLATE: LEGO1 0x100494a0
// _Tree<LegoBEWithFloat *,LegoBEWithFloat *,multiset<LegoBEWithFloat *,LegoBEWithFloatComparator,allocator<LegoBEWithFloat *> >::_Kfn,LegoBEWithFloatComparator,allocator<LegoBEWithFloat *> >::iterator::_Inc

// TEMPLATE: LEGO1 0x100494e0
// _Tree<LegoBEWithFloat *,LegoBEWithFloat *,multiset<LegoBEWithFloat *,LegoBEWithFloatComparator,allocator<LegoBEWithFloat *> >::_Kfn,LegoBEWithFloatComparator,allocator<LegoBEWithFloat *> >::~_Tree<LegoBEWithFloat *,LegoBEWithFloat *,multiset<LegoBEWithFlo

// TEMPLATE: LEGO1 0x100495b0
// _Tree<LegoBEWithFloat *,LegoBEWithFloat *,multiset<LegoBEWithFloat *,LegoBEWithFloatComparator,allocator<LegoBEWithFloat *> >::_Kfn,LegoBEWithFloatComparator,allocator<LegoBEWithFloat *> >::insert

// TEMPLATE: LEGO1 0x10049840
// _Tree<LegoBEWithFloat *,LegoBEWithFloat *,multiset<LegoBEWithFloat *,LegoBEWithFloatComparator,allocator<LegoBEWithFloat *> >::_Kfn,LegoBEWithFloatComparator,allocator<LegoBEWithFloat *> >::iterator::_Dec

// TEMPLATE: LEGO1 0x10049890
// _Tree<LegoBEWithFloat *,LegoBEWithFloat *,multiset<LegoBEWithFloat *,LegoBEWithFloatComparator,allocator<LegoBEWithFloat *> >::_Kfn,LegoBEWithFloatComparator,allocator<LegoBEWithFloat *> >::erase

// TEMPLATE: LEGO1 0x10049cf0
// _Tree<LegoBEWithFloat *,LegoBEWithFloat *,multiset<LegoBEWithFloat *,LegoBEWithFloatComparator,allocator<LegoBEWithFloat *> >::_Kfn,LegoBEWithFloatComparator,allocator<LegoBEWithFloat *> >::_Buynode

// TEMPLATE: LEGO1 0x10049d50
// _Tree<LegoBEWithFloat *,LegoBEWithFloat *,multiset<LegoBEWithFloat *,LegoBEWithFloatComparator,allocator<LegoBEWithFloat *> >::_Kfn,LegoBEWithFloatComparator,allocator<LegoBEWithFloat *> >::_Init

// TEMPLATE: LEGO1 0x10049e00
// _Tree<LegoBEWithFloat *,LegoBEWithFloat *,multiset<LegoBEWithFloat *,LegoBEWithFloatComparator,allocator<LegoBEWithFloat *> >::_Kfn,LegoBEWithFloatComparator,allocator<LegoBEWithFloat *> >::_Insert

// TEMPLATE: LEGO1 0x10049d10
// _Tree<LegoBEWithFloat *,LegoBEWithFloat *,multiset<LegoBEWithFloat *,LegoBEWithFloatComparator,allocator<LegoBEWithFloat *> >::_Kfn,LegoBEWithFloatComparator,allocator<LegoBEWithFloat *> >::_Erase

// TEMPLATE: LEGO1 0x1004a090
// _Tree<LegoBEWithFloat *,LegoBEWithFloat *,multiset<LegoBEWithFloat *,LegoBEWithFloatComparator,allocator<LegoBEWithFloat *> >::_Kfn,LegoBEWithFloatComparator,allocator<LegoBEWithFloat *> >::_Lrotate

// TEMPLATE: LEGO1 0x1004a0f0
// _Tree<LegoBEWithFloat *,LegoBEWithFloat *,multiset<LegoBEWithFloat *,LegoBEWithFloatComparator,allocator<LegoBEWithFloat *> >::_Kfn,LegoBEWithFloatComparator,allocator<LegoBEWithFloat *> >::_Rrotate

// TEMPLATE: LEGO1 0x1004a150
// List<LegoBEWithFloat>::~List<LegoBEWithFloat>

// TEMPLATE: LEGO1 0x1004a1a0
// Multiset<LegoBEWithFloat *,LegoBEWithFloatComparator>::~Multiset<LegoBEWithFloat *,LegoBEWithFloatComparator>

// TEMPLATE: LEGO1 0x1004a1f0
// multiset<LegoBEWithFloat *,LegoBEWithFloatComparator,allocator<LegoBEWithFloat *> >::~multiset<LegoBEWithFloat *,LegoBEWithFloatComparator,allocator<LegoBEWithFloat *> >

// TEMPLATE: LEGO1 0x1004a760
// ?_Construct@@YAXPAPAULegoBEWithFloat@@ABQAU1@@Z

// TEMPLATE: LEGO1 0x1004a780
// ?_Construct@@YAXPAPAULegoPathCtrlEdge@@ABQAU1@@Z

// GLOBAL: LEGO1 0x100f4360
// _Tree<LegoPathCtrlEdge *,LegoPathCtrlEdge *,set<LegoPathCtrlEdge *,LegoPathCtrlEdgeCompare,allocator<LegoPathCtrlEdge *> >::_Kfn,LegoPathCtrlEdgeCompare,allocator<LegoPathCtrlEdge *> >::_Nil

// GLOBAL: LEGO1 0x100f4364
// _Tree<LegoBEWithFloat *,LegoBEWithFloat *,multiset<LegoBEWithFloat *,LegoBEWithFloatComparator,allocator<LegoBEWithFloat *> >::_Kfn,LegoBEWithFloatComparator,allocator<LegoBEWithFloat *> >::_Nil
// clang-format on

#endif // LEGOPATHCONTROLLER_H
