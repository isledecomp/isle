#ifndef LEGOPATHCONTROLLER_H
#define LEGOPATHCONTROLLER_H

#include "decomp.h"
#include "geom/legowegedge.h"
#include "legopathboundary.h"
#include "legopathactor.h"
#include "legopathstruct.h"
#include "mxstl/stlcompat.h"

class LegoAnimPresenter;
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
struct LegoPathCtrlEdge : public LegoOrientedEdge {};

struct LegoPathCtrlEdgeCompare {
	MxU32 operator()(const LegoPathCtrlEdge* p_lhs, const LegoPathCtrlEdge* p_rhs) const
	{
		return (COMPARE_POINTER_TYPE) p_lhs < (COMPARE_POINTER_TYPE) p_rhs;
	}
};

typedef set<LegoPathCtrlEdge*, LegoPathCtrlEdgeCompare> LegoPathCtrlEdgeSet;

// VTABLE: LEGO1 0x100d7d60
// VTABLE: BETA10 0x101bde20
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
		LegoOrientedEdge* m_edge;         // 0x04
	};

	LegoPathController();
	~LegoPathController() override { Destroy(); }

	MxResult Tickle() override; // vtable+08

	// FUNCTION: LEGO1 0x10045110
	// FUNCTION: BETA10 0x100ba560
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
	void AddPresenterIfInRange(LegoAnimPresenter* p_presenter);
	void RemovePresenterFromBoundaries(LegoAnimPresenter* p_presenter);
	MxResult GetBoundaries(LegoPathBoundary*& p_boundaries, MxS32& p_numL);
	LegoPathBoundary* GetPathBoundary(const char* p_name);
	void Enable(MxBool p_enable);
	void SetWorld(LegoWorld* p_world);
	MxResult FindPath(
		LegoPathEdgeContainer* p_grec,
		const Vector3& p_oldPosition,
		const Vector3& p_oldDirection,
		LegoPathBoundary* p_oldBoundary,
		const Vector3& p_newPosition,
		const Vector3& p_newDirection,
		LegoPathBoundary* p_newBoundary,
		LegoU8 p_mask,
		MxFloat* p_distance
	);
	MxS32 GetNextPathEdge(
		LegoPathEdgeContainer& p_grec,
		Vector3& p_position,
		Vector3& p_direction,
		float p_f1,
		LegoOrientedEdge*& p_edge,
		LegoPathBoundary*& p_boundary
	);
	MxResult FindIntersectionBoundary(
		Vector3& p_param1,
		Vector3& p_param2,
		Mx3DPointFloat* p_param3,
		LegoPathBoundary*& p_boundary,
		MxFloat& p_param5
	);

	// FUNCTION: BETA10 0x100e0160
	MxBool ActorExists(LegoPathActor* p_actor) { return m_actors.find(p_actor) == m_actors.end() ? FALSE : TRUE; }

	static MxResult Init();
	static MxResult Reset();

	// FUNCTION: BETA10 0x100cf580
	static LegoOrientedEdge* GetControlEdgeA(MxS32 p_index) { return g_ctrlEdgesA[p_index].m_edge; }

	// FUNCTION: BETA10 0x100cf5b0
	static LegoPathBoundary* GetControlBoundaryA(MxS32 p_index) { return g_ctrlBoundariesA[p_index].m_boundary; }

	// These two are an educated guess because BETA10 does not have the g_ctrl.*B globals
	static LegoOrientedEdge* GetControlEdgeB(MxS32 p_index) { return g_ctrlEdgesB[p_index].m_edge; }
	static LegoPathBoundary* GetControlBoundaryB(MxS32 p_index) { return g_ctrlBoundariesB[p_index].m_boundary; }

private:
	void AnimateActors();
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
	static MxU32 BothSameComparison(MxFloat p_v1, MxFloat p_v2, MxFloat p_a, MxFloat p_b)
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
	Mx3DPointFloat* m_nodes;        // 0x10
	LegoPathStruct* m_structs;      // 0x14
	MxU16 m_numL;                   // 0x18 Number of boundaries
	MxU16 m_numE;                   // 0x1a Number of edges
	MxU16 m_numN;                   // 0x1c Number of nodes
	MxU16 m_numT;                   // 0x1e Number of structs
	LegoPathCtrlEdgeSet m_pfsE;     // 0x20
	LegoPathActorSet m_actors;      // 0x30

	// Names verified by BETA10
	static CtrlBoundary* g_ctrlBoundariesA;
	static CtrlEdge* g_ctrlEdgesA;

	static const char* g_ctrlBoundariesNamesA[];
	static const char* g_ctrlBoundariesNamesB[];
	static CtrlBoundary* g_ctrlBoundariesB;
	static CtrlEdge* g_ctrlEdgesB;
};

// clang-format off
// TEMPLATE: LEGO1 0x1001fd70 SYMBOL
// ?_Lbound@?$_Tree@PAVLegoPathActor@@PAV1@U_Kfn@?$set@PAVLegoPathActor@@ULegoPathActorSetCompare@@V?$allocator@PAVLegoPathActor@@@@@@ULegoPathActorSetCompare@@V?$allocator@PAVLegoPathActor@@@@@@IBEPAU_Node@1@ABQAVLegoPathActor@@@Z

// TEMPLATE: LEGO1 0x1002c4a0 SYMBOL
// ?_Buynode@?$_Tree@PAVLegoPathActor@@PAV1@U_Kfn@?$set@PAVLegoPathActor@@ULegoPathActorSetCompare@@V?$allocator@PAVLegoPathActor@@@@@@ULegoPathActorSetCompare@@V?$allocator@PAVLegoPathActor@@@@@@IAEPAU_Node@1@PAU21@W4_Redbl@1@@Z

// TEMPLATE: LEGO1 0x100451a0 SYMBOL
// ??1?$_Tree@PAULegoPathCtrlEdge@@PAU1@U_Kfn@?$set@PAULegoPathCtrlEdge@@ULegoPathCtrlEdgeCompare@@V?$allocator@PAULegoPathCtrlEdge@@@@@@ULegoPathCtrlEdgeCompare@@V?$allocator@PAULegoPathCtrlEdge@@@@@@QAE@XZ

// TEMPLATE: LEGO1 0x10045270 SYMBOL
// ?_Inc@iterator@?$_Tree@PAULegoPathCtrlEdge@@PAU1@U_Kfn@?$set@PAULegoPathCtrlEdge@@ULegoPathCtrlEdgeCompare@@V?$allocator@PAULegoPathCtrlEdge@@@@@@ULegoPathCtrlEdgeCompare@@V?$allocator@PAULegoPathCtrlEdge@@@@@@QAEXXZ

// TEMPLATE: LEGO1 0x100452b0
// ?erase@?$_Tree@PAULegoPathCtrlEdge@@PAU1@U_Kfn@?$set@PAULegoPathCtrlEdge@@ULegoPathCtrlEdgeCompare@@V?$allocator@PAULegoPathCtrlEdge@@@@@@ULegoPathCtrlEdgeCompare@@V?$allocator@PAULegoPathCtrlEdge@@@@@@QAE?AViterator@1@V21@@Z

// TEMPLATE: LEGO1 0x10045700 SYMBOL
// ?_Erase@?$_Tree@PAULegoPathCtrlEdge@@PAU1@U_Kfn@?$set@PAULegoPathCtrlEdge@@ULegoPathCtrlEdgeCompare@@V?$allocator@PAULegoPathCtrlEdge@@@@@@ULegoPathCtrlEdgeCompare@@V?$allocator@PAULegoPathCtrlEdge@@@@@@IAEXPAU_Node@1@@Z

// TEMPLATE: LEGO1 0x100457e0
// Set<LegoPathCtrlEdge *,LegoPathCtrlEdgeCompare>::~Set<LegoPathCtrlEdge *,LegoPathCtrlEdgeCompare>

// TEMPLATE: LEGO1 0x10045830 SYMBOL
// ??1?$set@PAULegoPathCtrlEdge@@ULegoPathCtrlEdgeCompare@@V?$allocator@PAULegoPathCtrlEdge@@@@@@QAE@XZ

// TEMPLATE: LEGO1 0x10046640 SYMBOL
// ?find@?$_Tree@PAVLegoAnimPresenter@@PAV1@U_Kfn@?$set@PAVLegoAnimPresenter@@ULegoAnimPresenterSetCompare@@V?$allocator@PAVLegoAnimPresenter@@@@@@ULegoAnimPresenterSetCompare@@V?$allocator@PAVLegoAnimPresenter@@@@@@QBE?AVconst_iterator@1@ABQAVLegoAnimPresen

// TEMPLATE: LEGO1 0x100468c0 SYMBOL
// ?_Ubound@?$_Tree@PAVLegoPathActor@@PAV1@U_Kfn@?$set@PAVLegoPathActor@@ULegoPathActorSetCompare@@V?$allocator@PAVLegoPathActor@@@@@@ULegoPathActorSetCompare@@V?$allocator@PAVLegoPathActor@@@@@@IBEPAU_Node@1@ABQAVLegoPathActor@@@Z

// TEMPLATE: LEGO1 0x10047550 SYMBOL
// ?_Insert@?$_Tree@PAULegoPathCtrlEdge@@PAU1@U_Kfn@?$set@PAULegoPathCtrlEdge@@ULegoPathCtrlEdgeCompare@@V?$allocator@PAULegoPathCtrlEdge@@@@@@ULegoPathCtrlEdgeCompare@@V?$allocator@PAULegoPathCtrlEdge@@@@@@IAE?AViterator@1@PAU_Node@1@0ABQAULegoPathCtrlEdge@

// TEMPLATE: LEGO1 0x100474e0 SYMBOL
// ?_Dec@iterator@?$_Tree@PAULegoPathCtrlEdge@@PAU1@U_Kfn@?$set@PAULegoPathCtrlEdge@@ULegoPathCtrlEdgeCompare@@V?$allocator@PAULegoPathCtrlEdge@@@@@@ULegoPathCtrlEdgeCompare@@V?$allocator@PAULegoPathCtrlEdge@@@@@@QAEXXZ

// TEMPLATE: LEGO1 0x10047530 SYMBOL
// ?_Buynode@?$_Tree@PAULegoPathCtrlEdge@@PAU1@U_Kfn@?$set@PAULegoPathCtrlEdge@@ULegoPathCtrlEdgeCompare@@V?$allocator@PAULegoPathCtrlEdge@@@@@@ULegoPathCtrlEdgeCompare@@V?$allocator@PAULegoPathCtrlEdge@@@@@@IAEPAU_Node@1@PAU21@W4_Redbl@1@@Z

// TEMPLATE: LEGO1 0x100477d0 SYMBOL
// ?_Lrotate@?$_Tree@PAULegoPathCtrlEdge@@PAU1@U_Kfn@?$set@PAULegoPathCtrlEdge@@ULegoPathCtrlEdgeCompare@@V?$allocator@PAULegoPathCtrlEdge@@@@@@ULegoPathCtrlEdgeCompare@@V?$allocator@PAULegoPathCtrlEdge@@@@@@IAEXPAU_Node@1@@Z

// TEMPLATE: LEGO1 0x10047830 SYMBOL
// ?_Rrotate@?$_Tree@PAULegoPathCtrlEdge@@PAU1@U_Kfn@?$set@PAULegoPathCtrlEdge@@ULegoPathCtrlEdgeCompare@@V?$allocator@PAULegoPathCtrlEdge@@@@@@ULegoPathCtrlEdgeCompare@@V?$allocator@PAULegoPathCtrlEdge@@@@@@IAEXPAU_Node@1@@Z

// SYNTHETIC: LEGO1 0x10047940
// LegoPathCtrlEdge::`vector deleting destructor'

// SYNTHETIC: LEGO1 0x100479d0
// LegoPathCtrlEdge::LegoPathCtrlEdge

// SYNTHETIC: LEGO1 0x10047a30
// LegoPathCtrlEdge::~LegoPathCtrlEdge

// SYNTHETIC: LEGO1 0x10047ae0
// LegoOrientedEdge::~LegoOrientedEdge

// TEMPLATE: LEGO1 0x10048f00 SYMBOL
// ?begin@?$list@ULegoBoundaryEdge@@V?$allocator@ULegoBoundaryEdge@@@@@@QAE?AViterator@1@XZ

// TEMPLATE: LEGO1 0x10048f10 SYMBOL
// ?insert@?$list@ULegoBoundaryEdge@@V?$allocator@ULegoBoundaryEdge@@@@@@QAE?AViterator@1@V21@ABULegoBoundaryEdge@@@Z

// TEMPLATE: LEGO1 0x10048f70 SYMBOL
// ?erase@?$list@ULegoBoundaryEdge@@V?$allocator@ULegoBoundaryEdge@@@@@@QAE?AViterator@1@V21@@Z

// TEMPLATE: LEGO1 0x10048fc0 SYMBOL
// ??0?$_Tree@PAULegoPathCtrlEdge@@PAU1@U_Kfn@?$set@PAULegoPathCtrlEdge@@ULegoPathCtrlEdgeCompare@@V?$allocator@PAULegoPathCtrlEdge@@@@@@ULegoPathCtrlEdgeCompare@@V?$allocator@PAULegoPathCtrlEdge@@@@@@QAE@ABV0@@Z

// TEMPLATE: LEGO1 0x10049160
// ?erase@?$_Tree@PAULegoPathCtrlEdge@@PAU1@U_Kfn@?$set@PAULegoPathCtrlEdge@@ULegoPathCtrlEdgeCompare@@V?$allocator@PAULegoPathCtrlEdge@@@@@@ULegoPathCtrlEdgeCompare@@V?$allocator@PAULegoPathCtrlEdge@@@@@@QAEIABQAULegoPathCtrlEdge@@@Z

// TEMPLATE: LEGO1 0x10049290 SYMBOL
// ?find@?$_Tree@PAULegoPathCtrlEdge@@PAU1@U_Kfn@?$set@PAULegoPathCtrlEdge@@ULegoPathCtrlEdgeCompare@@V?$allocator@PAULegoPathCtrlEdge@@@@@@ULegoPathCtrlEdgeCompare@@V?$allocator@PAULegoPathCtrlEdge@@@@@@QBE?AVconst_iterator@1@ABQAULegoPathCtrlEdge@@@Z

// TEMPLATE: LEGO1 0x100492f0 SYMBOL
// ?_Copy@?$_Tree@PAULegoPathCtrlEdge@@PAU1@U_Kfn@?$set@PAULegoPathCtrlEdge@@ULegoPathCtrlEdgeCompare@@V?$allocator@PAULegoPathCtrlEdge@@@@@@ULegoPathCtrlEdgeCompare@@V?$allocator@PAULegoPathCtrlEdge@@@@@@IAEPAU_Node@1@PAU21@0@Z

// TEMPLATE: LEGO1 0x10049370 SYMBOL
// ?_Ubound@?$_Tree@PAULegoPathCtrlEdge@@PAU1@U_Kfn@?$set@PAULegoPathCtrlEdge@@ULegoPathCtrlEdgeCompare@@V?$allocator@PAULegoPathCtrlEdge@@@@@@ULegoPathCtrlEdgeCompare@@V?$allocator@PAULegoPathCtrlEdge@@@@@@IBEPAU_Node@1@ABQAULegoPathCtrlEdge@@@Z

// TEMPLATE: LEGO1 0x100493a0 SYMBOL
// ??1?$list@ULegoBEWithMidpoint@@V?$allocator@ULegoBEWithMidpoint@@@@@@QAE@XZ

// TEMPLATE: LEGO1 0x10049410 SYMBOL
// ?insert@?$list@ULegoBEWithMidpoint@@V?$allocator@ULegoBEWithMidpoint@@@@@@QAE?AViterator@1@V21@ABULegoBEWithMidpoint@@@Z

// TEMPLATE: LEGO1 0x10049470 SYMBOL
// ?_Buynode@?$list@ULegoBEWithMidpoint@@V?$allocator@ULegoBEWithMidpoint@@@@@@IAEPAU_Node@1@PAU21@0@Z

// TEMPLATE: LEGO1 0x100494a0 SYMBOL
// ?_Inc@iterator@?$_Tree@PAULegoBEWithMidpoint@@PAU1@U_Kfn@?$multiset@PAULegoBEWithMidpoint@@ULegoBEWithMidpointComparator@@V?$allocator@PAULegoBEWithMidpoint@@@@@@ULegoBEWithMidpointComparator@@V?$allocator@PAULegoBEWithMidpoint@@@@@@QAEXXZ

// TEMPLATE: LEGO1 0x100494e0 SYMBOL
// ??1?$_Tree@PAULegoBEWithMidpoint@@PAU1@U_Kfn@?$multiset@PAULegoBEWithMidpoint@@ULegoBEWithMidpointComparator@@V?$allocator@PAULegoBEWithMidpoint@@@@@@ULegoBEWithMidpointComparator@@V?$allocator@PAULegoBEWithMidpoint@@@@@@QAE@XZ

// TEMPLATE: LEGO1 0x100495b0 SYMBOL
// ?insert@?$_Tree@PAULegoBEWithMidpoint@@PAU1@U_Kfn@?$multiset@PAULegoBEWithMidpoint@@ULegoBEWithMidpointComparator@@V?$allocator@PAULegoBEWithMidpoint@@@@@@ULegoBEWithMidpointComparator@@V?$allocator@PAULegoBEWithMidpoint@@@@@@QAE?AU?$pair@Viterator@?$_Tre

// TEMPLATE: LEGO1 0x10049840 SYMBOL
// ?_Dec@iterator@?$_Tree@PAULegoBEWithMidpoint@@PAU1@U_Kfn@?$multiset@PAULegoBEWithMidpoint@@ULegoBEWithMidpointComparator@@V?$allocator@PAULegoBEWithMidpoint@@@@@@ULegoBEWithMidpointComparator@@V?$allocator@PAULegoBEWithMidpoint@@@@@@QAEXXZ

// TEMPLATE: LEGO1 0x10049890 SYMBOL
// ?erase@?$_Tree@PAULegoBEWithMidpoint@@PAU1@U_Kfn@?$multiset@PAULegoBEWithMidpoint@@ULegoBEWithMidpointComparator@@V?$allocator@PAULegoBEWithMidpoint@@@@@@ULegoBEWithMidpointComparator@@V?$allocator@PAULegoBEWithMidpoint@@@@@@QAE?AViterator@1@V21@@Z

// TEMPLATE: LEGO1 0x10049cf0 SYMBOL
// ?_Buynode@?$_Tree@PAULegoBEWithMidpoint@@PAU1@U_Kfn@?$multiset@PAULegoBEWithMidpoint@@ULegoBEWithMidpointComparator@@V?$allocator@PAULegoBEWithMidpoint@@@@@@ULegoBEWithMidpointComparator@@V?$allocator@PAULegoBEWithMidpoint@@@@@@IAEPAU_Node@1@PAU21@W4_Redb

// TEMPLATE: LEGO1 0x10049d50 SYMBOL
// ?_Init@?$_Tree@PAULegoBEWithMidpoint@@PAU1@U_Kfn@?$multiset@PAULegoBEWithMidpoint@@ULegoBEWithMidpointComparator@@V?$allocator@PAULegoBEWithMidpoint@@@@@@ULegoBEWithMidpointComparator@@V?$allocator@PAULegoBEWithMidpoint@@@@@@IAEXXZ

// TEMPLATE: LEGO1 0x10049e00 SYMBOL
// ?_Insert@?$_Tree@PAULegoBEWithMidpoint@@PAU1@U_Kfn@?$multiset@PAULegoBEWithMidpoint@@ULegoBEWithMidpointComparator@@V?$allocator@PAULegoBEWithMidpoint@@@@@@ULegoBEWithMidpointComparator@@V?$allocator@PAULegoBEWithMidpoint@@@@@@IAE?AViterator@1@PAU_Node@1@

// TEMPLATE: LEGO1 0x10049d10 SYMBOL
// ?_Erase@?$_Tree@PAULegoBEWithMidpoint@@PAU1@U_Kfn@?$multiset@PAULegoBEWithMidpoint@@ULegoBEWithMidpointComparator@@V?$allocator@PAULegoBEWithMidpoint@@@@@@ULegoBEWithMidpointComparator@@V?$allocator@PAULegoBEWithMidpoint@@@@@@IAEXPAU_Node@1@@Z

// TEMPLATE: LEGO1 0x1004a090 SYMBOL
// ?_Lrotate@?$_Tree@PAULegoBEWithMidpoint@@PAU1@U_Kfn@?$multiset@PAULegoBEWithMidpoint@@ULegoBEWithMidpointComparator@@V?$allocator@PAULegoBEWithMidpoint@@@@@@ULegoBEWithMidpointComparator@@V?$allocator@PAULegoBEWithMidpoint@@@@@@IAEXPAU_Node@1@@Z

// TEMPLATE: LEGO1 0x1004a0f0 SYMBOL
// ?_Rrotate@?$_Tree@PAULegoBEWithMidpoint@@PAU1@U_Kfn@?$multiset@PAULegoBEWithMidpoint@@ULegoBEWithMidpointComparator@@V?$allocator@PAULegoBEWithMidpoint@@@@@@ULegoBEWithMidpointComparator@@V?$allocator@PAULegoBEWithMidpoint@@@@@@IAEXPAU_Node@1@@Z

// TEMPLATE: LEGO1 0x1004a150
// List<LegoBEWithMidpoint>::~List<LegoBEWithMidpoint>

// TEMPLATE: LEGO1 0x1004a1a0
// Multiset<LegoBEWithMidpoint *,LegoBEWithMidpointComparator>::~Multiset<LegoBEWithMidpoint *,LegoBEWithMidpointComparator>

// TEMPLATE: LEGO1 0x1004a1f0 SYMBOL
// ??1?$multiset@PAULegoBEWithMidpoint@@ULegoBEWithMidpointComparator@@V?$allocator@PAULegoBEWithMidpoint@@@@@@QAE@XZ

// TEMPLATE: LEGO1 0x1004a760
// ?_Construct@@YAXPAPAULegoBEWithMidpoint@@ABQAU1@@Z

// TEMPLATE: LEGO1 0x1004a780
// ?_Construct@@YAXPAPAULegoPathCtrlEdge@@ABQAU1@@Z

// GLOBAL: LEGO1 0x100f4360
// _Tree<LegoPathCtrlEdge *,LegoPathCtrlEdge *,set<LegoPathCtrlEdge *,LegoPathCtrlEdgeCompare,allocator<LegoPathCtrlEdge *>>::_Kfn,LegoPathCtrlEdgeCompare,allocator<LegoPathCtrlEdge *>>::_Nil

// GLOBAL: LEGO1 0x100f4364
// _Tree<LegoBEWithMidpoint *,LegoBEWithMidpoint *,multiset<LegoBEWithMidpoint *,LegoBEWithMidpointComparator,allocator<LegoBEWithMidpoint *>>::_Kfn,LegoBEWithMidpointComparator,allocator<LegoBEWithMidpoint *>>::_Nil
// clang-format on

#endif // LEGOPATHCONTROLLER_H
