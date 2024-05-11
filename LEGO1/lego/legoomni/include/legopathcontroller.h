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

// VTABLE: LEGO1 0x100d7da8
// SIZE 0x40
class LegoPathCtrlEdge : public LegoUnknown100db7f4 {};

struct LegoPathCtrlEdgeCompare {
	MxU32 operator()(const LegoPathCtrlEdge* p_lhs, const LegoPathCtrlEdge* p_rhs) const
	{
		return (MxS32) p_lhs < (MxS32) p_rhs;
	}
};

typedef set<LegoPathCtrlEdge*, LegoPathCtrlEdgeCompare> LegoPathCtrlEdgeSet;

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

	virtual void Create(MxU8* p_data, Vector3& p_location, MxAtomId& p_trigger); // vtable+0x14
	virtual void Destroy();                                                      // vtable+0x18

	MxResult FUN_10045c20(
		LegoPathActor* p_actor,
		const char* p_name,
		MxS32 p_src,
		float p_srcScale,
		MxS32 p_dest,
		float p_destScale
	);
	undefined4 FUN_10046770(LegoPathActor* p_actor);
	void FUN_100468f0(LegoAnimPresenter* p_presenter);
	void FUN_10046930(LegoAnimPresenter* p_presenter);
	MxResult FUN_10046b30(LegoPathBoundary** p_path, MxS32& p_value);
	LegoPathBoundary* GetPathBoundary(const char* p_name);
	void Enable(MxBool p_enable);
	void FUN_10046bb0(LegoWorld* p_world);

private:
	MxResult Read(LegoStorage* p_storage);
	MxResult FUN_10047b30(LegoStorage* p_storage);
	MxResult FUN_10047c10(LegoStorage* p_storage);
	MxResult FUN_10047e90(LegoStorage* p_storage);
	static MxResult FUN_100482b0(LegoStorage* p_storage, Mx3DPointFloat&);

	LegoPathBoundary* m_unk0x08; // 0x08
	LegoPathCtrlEdge* m_unk0x0c; // 0x0c
	Mx3DPointFloat* m_unk0x10;   // 0x10
	LegoPathStruct* m_unk0x14;   // 0x14
	MxU16 m_numL;                // 0x18
	MxU16 m_numE;                // 0x1a
	MxU16 m_numN;                // 0x1c
	MxU16 m_numT;                // 0x1e
	LegoPathCtrlEdgeSet m_pfsE;  // 0x20
	LegoPathActorSet m_actors;   // 0x30
};

// clang-format off
// TEMPLATE: LEGO1 0x100451a0
// _Tree<LegoPathCtrlEdge *,LegoPathCtrlEdge *,set<LegoPathCtrlEdge *,LegoPathCtrlEdgeCompare,allocator<LegoPathCtrlEdge *> >::_Kfn,LegoPathCtrlEdgeCompare,allocator<LegoPathCtrlEdge *> >::~_Tree<LegoPathCtrlEdge *,LegoPathCtrlEdge *,set<LegoPathCtrlEdge *,LegoPathControl

// TEMPLATE: LEGO1 0x100457e0
// Set<LegoPathCtrlEdge *,LegoPathCtrlEdgeCompare>::~Set<LegoPathCtrlEdge *,LegoPathCtrlEdgeCompare>

// TEMPLATE: LEGO1 0x10045830
// set<LegoPathCtrlEdge *,LegoPathCtrlEdgeCompare,allocator<LegoPathCtrlEdge *> >::~set<LegoPathCtrlEdge *,LegoPathCtrlEdgeCompare,allocator<LegoPathCtrlEdge *> >

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

// TEMPLATE: LEGO1 0x1004a780
// _Construct

// GLOBAL: LEGO1 0x100f4360
// _Tree<LegoPathCtrlEdge *,LegoPathCtrlEdge *,set<LegoPathCtrlEdge *,LegoPathCtrlEdgeCompare,allocator<LegoPathCtrlEdge *> >::_Kfn,LegoPathCtrlEdgeCompare,allocator<LegoPathCtrlEdge *> >::_Nil
// clang-format on

#endif // LEGOPATHCONTROLLER_H
