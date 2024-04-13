#ifndef LEGOANIMPRESENTER_H
#define LEGOANIMPRESENTER_H

#include "anim/legoanim.h"
#include "legoroilist.h"
#include "mxgeometry/mxgeometry3d.h"
#include "mxvideopresenter.h"

class LegoWorld;
class LegoAnimClass;
class LegoAnimActor;

struct LegoAnimStructComparator {
	MxBool operator()(const char* const& p_a, const char* const& p_b) const { return strcmp(p_a, p_b) < 0; }
};

// SIZE 0x08
struct LegoAnimStruct {
	LegoROI* m_roi; // 0x00
	MxU32 m_index;  // 0x04
};

typedef map<const char*, LegoAnimStruct, LegoAnimStructComparator> LegoAnimPresenterMap;

// VTABLE: LEGO1 0x100d90c8
// SIZE 0xbc
class LegoAnimPresenter : public MxVideoPresenter {
public:
	enum {
		c_bit2 = 0x02
	};

	LegoAnimPresenter();
	~LegoAnimPresenter() override;

	// FUNCTION: LEGO1 0x10068530
	inline const char* ClassName() const override // vtable+0x0c
	{
		// STRING: LEGO1 0x100f071c
		return "LegoAnimPresenter";
	}

	// FUNCTION: LEGO1 0x10068540
	inline MxBool IsA(const char* p_name) const override // vtable+0x10
	{
		return !strcmp(p_name, LegoAnimPresenter::ClassName()) || MxVideoPresenter::IsA(p_name);
	}

	void ReadyTickle() override;                                                           // vtable+0x18
	void StartingTickle() override;                                                        // vtable+0x1c
	void StreamingTickle() override;                                                       // vtable+0x20
	void DoneTickle() override;                                                            // vtable+0x2c
	void ParseExtra() override;                                                            // vtable+0x30
	MxResult AddToManager() override;                                                      // vtable+0x34
	void Destroy() override;                                                               // vtable+0x38
	MxResult StartAction(MxStreamController* p_controller, MxDSAction* p_action) override; // vtable+0x3c
	void EndAction() override;                                                             // vtable+0x40
	void PutFrame() override;                                                              // vtable+0x6c
	virtual MxResult CreateAnim(MxStreamChunk* p_chunk);                                   // vtable+0x88
	virtual void VTable0x8c();                                                             // vtable+0x8c
	virtual void VTable0x90();                                                             // vtable+0x90
	virtual void VTable0x94();                                                             // vtable+0x94
	virtual void VTable0x98();                                                             // vtable+0x98

	// FUNCTION: LEGO1 0x1000c990
	virtual LegoROI** VTable0x9c(MxU32& p_unk0x6c)
	{
		p_unk0x6c = m_unk0x6c;
		return m_unk0x68;
	} // vtable+0x9c

	virtual void VTable0xa0(); // vtable+0xa0

	void FUN_1006d680(LegoAnimActor* p_actor, MxFloat p_value);

	inline LegoAnim* GetAnimation() { return m_anim; }

	const char* GetActionObjectName();

protected:
	void Init();
	void Destroy(MxBool p_fromDestructor);
	LegoChar* FUN_10069150(const LegoChar* p_und1);
	void FUN_100692b0();
	void FUN_100695c0();
	LegoChar* FUN_100697c0(const LegoChar* p_und1, const LegoChar* p_und2);
	LegoBool FUN_100698b0(const CompoundObject& p_rois, const LegoChar* p_und2);
	LegoROI* FUN_100699e0(const LegoChar* p_und);
	void FUN_10069b10();
	void FUN_1006a3c0(LegoAnimPresenterMap& p_map, LegoTreeNode* p_node, LegoROI* p_roi);
	void FUN_1006a4f0(LegoAnimPresenterMap& p_map, LegoAnimNodeData* p_data, const LegoChar* p_und, LegoROI* p_roi);
	LegoBool FUN_1006aba0();
	MxBool FUN_1006abb0(LegoTreeNode* p_node, LegoROI* p_roi);
	void FUN_1006ac90();
	void FUN_1006b9a0(LegoAnim* p_anim, MxLong p_time, Matrix4* p_matrix);
	void FUN_1006c8a0(MxBool p_bool);

	LegoAnim* m_anim;          // 0x64
	LegoROI** m_unk0x68;       // 0x68
	MxU32 m_unk0x6c;           // 0x6c
	LegoROIList* m_unk0x70;    // 0x70
	LegoROIList* m_unk0x74;    // 0x74
	MxMatrix* m_unk0x78;       // 0x78
	undefined4 m_unk0x7c;      // 0x7c
	LegoWorld* m_currentWorld; // 0x80
	MxAtomId m_animAtom;       // 0x84
	undefined4 m_unk0x88;      // 0x88
	LegoROI** m_unk0x8c;       // 0x8c
	const char** m_unk0x90;    // 0x90
	MxU8 m_unk0x94;            // 0x94
	undefined m_unk0x95;       // 0x95
	MxBool m_unk0x96;          // 0x96
	undefined m_unk0x97;       // 0x97
	undefined4 m_unk0x98;      // 0x98
	MxS16 m_unk0x9c;           // 0x9c
	undefined4 m_unk0xa0;      // 0xa0
	undefined4 m_unk0xa4;      // 0xa4
	Mx3DPointFloat m_unk0xa8;  // 0xa8
};

// clang-format off
// SYNTHETIC: LEGO1 0x10068650
// LegoAnimPresenter::`scalar deleting destructor'

// TEMPLATE: LEGO1 0x10069d80
// _Tree<char const *,pair<char const * const,LegoAnimStruct>,map<char const *,LegoAnimStruct,LegoAnimStructComparator,allocator<LegoAnimStruct> >::_Kfn,LegoAnimStructComparator,allocator<LegoAnimStruct> >::~_Tree<char const *,pair<char const * const,LegoAni

// TEMPLATE: LEGO1 0x1006a320
// Map<char const *,LegoAnimStruct,LegoAnimStructComparator>::~Map<char const *,LegoAnimStruct,LegoAnimStructComparator>

// TEMPLATE: LEGO1 0x1006a370
// map<char const *,LegoAnimStruct,LegoAnimStructComparator,allocator<LegoAnimStruct> >::~map<char const *,LegoAnimStruct,LegoAnimStructComparator,allocator<LegoAnimStruct> >

// TEMPLATE: LEGO1 0x1006a750
// _Tree<char const *,pair<char const * const,LegoAnimStruct>,map<char const *,LegoAnimStruct,LegoAnimStructComparator,allocator<LegoAnimStruct> >::_Kfn,LegoAnimStructComparator,allocator<LegoAnimStruct> >::iterator::_Dec

// TEMPLATE: LEGO1 0x1006a7a0
// _Tree<char const *,pair<char const * const,LegoAnimStruct>,map<char const *,LegoAnimStruct,LegoAnimStructComparator,allocator<LegoAnimStruct> >::_Kfn,LegoAnimStructComparator,allocator<LegoAnimStruct> >::_Insert

// GLOBAL: LEGO1 0x100f7688
// _Tree<char const *,pair<char const * const,LegoAnimStruct>,map<char const *,LegoAnimStruct,LegoAnimStructComparator,allocator<LegoAnimStruct> >::_Kfn,LegoAnimStructComparator,allocator<LegoAnimStruct> >::_Nil
// clang-format on

#endif // LEGOANIMPRESENTER_H
