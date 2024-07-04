#ifndef LEGOHIDEANIMPRESENTER_H
#define LEGOHIDEANIMPRESENTER_H

#include "decomp.h"
#include "legoloopinganimpresenter.h"

class LegoPathBoundary;

struct LegoHideAnimStructComparator {
	MxBool operator()(const char* const& p_a, const char* const& p_b) const { return strcmp(p_a, p_b) < 0; }
};

// SIZE 0x08
struct LegoHideAnimStruct {
	LegoPathBoundary* m_boundary; // 0x00
	MxU32 m_index;                // 0x04
};

typedef map<const char*, LegoHideAnimStruct, LegoHideAnimStructComparator> LegoHideAnimStructMap;

// VTABLE: LEGO1 0x100d9278
// SIZE 0xc4
class LegoHideAnimPresenter : public LegoLoopingAnimPresenter {
public:
	LegoHideAnimPresenter();
	~LegoHideAnimPresenter() override;

	// FUNCTION: BETA10 0x1005d4a0
	static const char* HandlerClassName()
	{
		// STRING: LEGO1 0x100f06cc
		return "LegoHideAnimPresenter";
	}

	// FUNCTION: LEGO1 0x1006d880
	// FUNCTION: BETA10 0x1005d470
	const char* ClassName() const override // vtable+0x0c
	{
		return HandlerClassName();
	}

	// FUNCTION: LEGO1 0x1006d890
	MxBool IsA(const char* p_name) const override // vtable+0x10
	{
		return !strcmp(p_name, ClassName()) || LegoAnimPresenter::IsA(p_name);
	}

	void ReadyTickle() override;      // vtable+0x18
	void StartingTickle() override;   // vtable+0x18
	MxResult AddToManager() override; // vtable+0x34
	void Destroy() override;          // vtable+0x38
	void EndAction() override;        // vtable+0x40
	void PutFrame() override;         // vtable+0x6c
	void VTable0x8c() override;       // vtable+0x8c
	void VTable0x90() override;       // vtable+0x90

	void FUN_1006db40(LegoTime p_time);

private:
	void Init();
	void Destroy(MxBool p_fromDestructor);
	void FUN_1006db60(LegoTreeNode* p_node, LegoTime p_time);
	void FUN_1006dc10();
	void FUN_1006e3f0(LegoHideAnimStructMap& p_map, LegoTreeNode* p_node);
	void FUN_1006e470(
		LegoHideAnimStructMap& p_map,
		LegoAnimNodeData* p_data,
		const char* p_name,
		LegoPathBoundary* p_boundary
	);

	LegoPathBoundary** m_boundaryMap; // 0xc0
};

// clang-format off
// SYNTHETIC: LEGO1 0x1006d9d0
// LegoHideAnimPresenter::`scalar deleting destructor'

// TEMPLATE: LEGO1 0x1006ddb0
// _Tree<char const *,pair<char const * const,LegoHideAnimStruct>,map<char const *,LegoHideAnimStruct,LegoHideAnimStructComparator,allocator<LegoHideAnimStruct> >::_Kfn,LegoHideAnimStructComparator,allocator<LegoHideAnimStruct> >::~_Tree<char const *,pair<ch

// TEMPLATE: LEGO1 0x1006de80
// _Tree<char const *,pair<char const * const,LegoHideAnimStruct>,map<char const *,LegoHideAnimStruct,LegoHideAnimStructComparator,allocator<LegoHideAnimStruct> >::_Kfn,LegoHideAnimStructComparator,allocator<LegoHideAnimStruct> >::iterator::_Inc

// TEMPLATE: LEGO1 0x1006dec0
// _Tree<char const *,pair<char const * const,LegoHideAnimStruct>,map<char const *,LegoHideAnimStruct,LegoHideAnimStructComparator,allocator<LegoHideAnimStruct> >::_Kfn,LegoHideAnimStructComparator,allocator<LegoHideAnimStruct> >::erase

// TEMPLATE: LEGO1 0x1006e310
// _Tree<char const *,pair<char const * const,LegoHideAnimStruct>,map<char const *,LegoHideAnimStruct,LegoHideAnimStructComparator,allocator<LegoHideAnimStruct> >::_Kfn,LegoHideAnimStructComparator,allocator<LegoHideAnimStruct> >::_Erase

// TEMPLATE: LEGO1 0x1006e350
// Map<char const *,LegoHideAnimStruct,LegoHideAnimStructComparator>::~Map<char const *,LegoHideAnimStruct,LegoHideAnimStructComparator>

// TEMPLATE: LEGO1 0x1006e3a0
// map<char const *,LegoHideAnimStruct,LegoHideAnimStructComparator,allocator<LegoHideAnimStruct> >::~map<char const *,LegoHideAnimStruct,LegoHideAnimStructComparator,allocator<LegoHideAnimStruct> >

// TEMPLATE: LEGO1 0x1006e6d0
// _Tree<char const *,pair<char const * const,LegoHideAnimStruct>,map<char const *,LegoHideAnimStruct,LegoHideAnimStructComparator,allocator<LegoHideAnimStruct> >::_Kfn,LegoHideAnimStructComparator,allocator<LegoHideAnimStruct> >::iterator::_Dec

// TEMPLATE: LEGO1 0x1006e720
// _Tree<char const *,pair<char const * const,LegoHideAnimStruct>,map<char const *,LegoHideAnimStruct,LegoHideAnimStructComparator,allocator<LegoHideAnimStruct> >::_Kfn,LegoHideAnimStructComparator,allocator<LegoHideAnimStruct> >::_Insert

// GLOBAL: LEGO1 0x100f768c
// _Tree<char const *,pair<char const * const,LegoHideAnimStruct>,map<char const *,LegoHideAnimStruct,LegoHideAnimStructComparator,allocator<LegoHideAnimStruct> >::_Kfn,LegoHideAnimStructComparator,allocator<LegoHideAnimStruct> >::_Nil
// clang-format on

#endif // LEGOHIDEANIMPRESENTER_H
