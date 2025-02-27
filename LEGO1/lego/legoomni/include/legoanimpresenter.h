#ifndef LEGOANIMPRESENTER_H
#define LEGOANIMPRESENTER_H

#include "legoroilist.h"
#include "mxatom.h"
#include "mxvideopresenter.h"

class LegoAnim;
class LegoWorld;
class LegoPathBoundary;
class MxMatrix;
class Vector3;

struct LegoAnimStructComparator {
	MxBool operator()(const char* const& p_a, const char* const& p_b) const { return strcmp(p_a, p_b) < 0; }
};

struct LegoAnimSubstComparator {
	MxBool operator()(const char* const& p_a, const char* const& p_b) const { return strcmp(p_a, p_b) < 0; }
};

// SIZE 0x08
struct LegoAnimStruct {
	LegoROI* m_roi; // 0x00
	MxU32 m_index;  // 0x04
};

typedef map<const char*, LegoAnimStruct, LegoAnimStructComparator> LegoAnimStructMap;
typedef map<const char*, const char*, LegoAnimSubstComparator> LegoAnimSubstMap;

// VTABLE: LEGO1 0x100d90c8
// VTABLE: BETA10 0x101baf90
// SIZE 0xbc
class LegoAnimPresenter : public MxVideoPresenter {
public:
	enum {
		c_hideOnStop = 0x01,
		c_mustSucceed = 0x02
	};

	LegoAnimPresenter();
	~LegoAnimPresenter() override;

	// FUNCTION: BETA10 0x10055300
	static const char* HandlerClassName()
	{
		// STRING: LEGO1 0x100f071c
		return "LegoAnimPresenter";
	}

	// FUNCTION: LEGO1 0x10068530
	// FUNCTION: BETA10 0x100552d0
	const char* ClassName() const override // vtable+0x0c
	{
		return HandlerClassName();
	}

	// FUNCTION: LEGO1 0x10068540
	MxBool IsA(const char* p_name) const override // vtable+0x10
	{
		return !strcmp(p_name, LegoAnimPresenter::ClassName()) || MxVideoPresenter::IsA(p_name);
	}

	void ReadyTickle() override;                                                                   // vtable+0x18
	void StartingTickle() override;                                                                // vtable+0x1c
	void StreamingTickle() override;                                                               // vtable+0x20
	void DoneTickle() override;                                                                    // vtable+0x2c
	void ParseExtra() override;                                                                    // vtable+0x30
	MxResult AddToManager() override;                                                              // vtable+0x34
	void Destroy() override;                                                                       // vtable+0x38
	MxResult StartAction(MxStreamController* p_controller, MxDSAction* p_action) override;         // vtable+0x3c
	void EndAction() override;                                                                     // vtable+0x40
	void PutFrame() override;                                                                      // vtable+0x6c
	virtual MxResult CreateAnim(MxStreamChunk* p_chunk);                                           // vtable+0x88
	virtual void VTable0x8c();                                                                     // vtable+0x8c
	virtual void VTable0x90();                                                                     // vtable+0x90
	virtual MxU32 VTable0x94(Vector3& p_v1, Vector3& p_v2, float p_f1, float p_f2, Vector3& p_v3); // vtable+0x94
	virtual MxResult VTable0x98(LegoPathBoundary* p_boundary);                                     // vtable+0x98

	// FUNCTION: LEGO1 0x1000c990
	virtual LegoROI** GetROIMap(MxU32& p_roiMapSize)
	{
		p_roiMapSize = m_roiMapSize;
		return m_roiMap;
	} // vtable+0x9c

	virtual void VTable0xa0(Matrix4& p_matrix); // vtable+0xa0

	MxResult FUN_1006afc0(MxMatrix*& p_matrix, float p_und);
	MxResult FUN_1006b140(LegoROI* p_roi);
	void FUN_1006c7a0();
	const char* GetActionObjectName();

	void SetCurrentWorld(LegoWorld* p_currentWorld) { m_currentWorld = p_currentWorld; }
	void SetUnknown0x0cTo1() { m_unk0x9c = 1; }
	void SetUnknown0xa0(Matrix4* p_unk0xa0) { m_unk0xa0 = p_unk0xa0; }

	LegoAnim* GetAnimation() { return m_anim; }

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
	void FUN_1006a3c0(LegoAnimStructMap& p_map, LegoTreeNode* p_node, LegoROI* p_roi);
	void FUN_1006a4f0(LegoAnimStructMap& p_map, LegoAnimNodeData* p_data, const LegoChar* p_und, LegoROI* p_roi);
	void FUN_1006aa60();
	void FUN_1006ab70();
	LegoBool FUN_1006aba0();
	MxBool FUN_1006abb0(LegoTreeNode* p_node, LegoROI* p_roi);
	void SubstituteVariables();
	void FUN_1006b900(LegoAnim* p_anim, MxLong p_time, Matrix4* p_matrix);
	void FUN_1006b9a0(LegoAnim* p_anim, MxLong p_time, Matrix4* p_matrix);
	void FUN_1006c8a0(MxBool p_bool);

	LegoAnim* m_anim;             // 0x64
	LegoROI** m_roiMap;           // 0x68
	MxU32 m_roiMapSize;           // 0x6c
	LegoROIList* m_unk0x70;       // 0x70
	LegoROIList* m_unk0x74;       // 0x74
	Matrix4* m_unk0x78;           // 0x78
	MxU32 m_flags;                // 0x7c
	LegoWorld* m_currentWorld;    // 0x80
	MxAtomId m_worldAtom;         // 0x84
	MxS32 m_worldId;              // 0x88
	LegoROI** m_unk0x8c;          // 0x8c
	char** m_unk0x90;             // 0x90
	MxU8 m_unk0x94;               // 0x94
	MxBool m_unk0x95;             // 0x95
	MxBool m_unk0x96;             // 0x96
	undefined m_unk0x97;          // 0x97
	LegoAnimSubstMap* m_substMap; // 0x98
	MxS16 m_unk0x9c;              // 0x9c
	Matrix4* m_unk0xa0;           // 0xa0

public:
	float m_unk0xa4;          // 0xa4
	Mx3DPointFloat m_unk0xa8; // 0xa8
};

// clang-format off
// SYNTHETIC: LEGO1 0x10068650
// LegoAnimPresenter::`scalar deleting destructor'

// TEMPLATE: LEGO1 0x100689c0
// map<char const *,char const *,LegoAnimSubstComparator,allocator<char const *> >::~map<char const *,char const *,LegoAnimSubstComparator,allocator<char const *> >

// TEMPLATE: LEGO1 0x10068a10
// _Tree<char const *,pair<char const * const,char const *>,map<char const *,char const *,LegoAnimSubstComparator,allocator<char const *> >::_Kfn,LegoAnimSubstComparator,allocator<char const *> >::~_Tree<char const *,pair<char const * const,char const *>,map

// TEMPLATE: LEGO1 0x10068ae0
// _Tree<char const *,pair<char const * const,char const *>,map<char const *,char const *,LegoAnimSubstComparator,allocator<char const *> >::_Kfn,LegoAnimSubstComparator,allocator<char const *> >::iterator::_Inc

// TEMPLATE: LEGO1 0x10068b20
// _Tree<char const *,pair<char const * const,char const *>,map<char const *,char const *,LegoAnimSubstComparator,allocator<char const *> >::_Kfn,LegoAnimSubstComparator,allocator<char const *> >::erase

// TEMPLATE: LEGO1 0x10068f70
// _Tree<char const *,pair<char const * const,char const *>,map<char const *,char const *,LegoAnimSubstComparator,allocator<char const *> >::_Kfn,LegoAnimSubstComparator,allocator<char const *> >::_Erase

// TEMPLATE: LEGO1 0x10069d80
// _Tree<char const *,pair<char const * const,LegoAnimStruct>,map<char const *,LegoAnimStruct,LegoAnimStructComparator,allocator<LegoAnimStruct> >::_Kfn,LegoAnimStructComparator,allocator<LegoAnimStruct> >::~_Tree<char const *,pair<char const * const,LegoAni

// TEMPLATE: LEGO1 0x10069e50
// _Tree<char const *,pair<char const * const,LegoAnimStruct>,map<char const *,LegoAnimStruct,LegoAnimStructComparator,allocator<LegoAnimStruct> >::_Kfn,LegoAnimStructComparator,allocator<LegoAnimStruct> >::iterator::_Inc

// TEMPLATE: LEGO1 0x10069e90
// _Tree<char const *,pair<char const * const,LegoAnimStruct>,map<char const *,LegoAnimStruct,LegoAnimStructComparator,allocator<LegoAnimStruct> >::_Kfn,LegoAnimStructComparator,allocator<LegoAnimStruct> >::erase

// TEMPLATE: LEGO1 0x1006a2e0
// _Tree<char const *,pair<char const * const,LegoAnimStruct>,map<char const *,LegoAnimStruct,LegoAnimStructComparator,allocator<LegoAnimStruct> >::_Kfn,LegoAnimStructComparator,allocator<LegoAnimStruct> >::_Erase

// TEMPLATE: LEGO1 0x1006a320
// Map<char const *,LegoAnimStruct,LegoAnimStructComparator>::~Map<char const *,LegoAnimStruct,LegoAnimStructComparator>

// TEMPLATE: LEGO1 0x1006a370
// map<char const *,LegoAnimStruct,LegoAnimStructComparator,allocator<LegoAnimStruct> >::~map<char const *,LegoAnimStruct,LegoAnimStructComparator,allocator<LegoAnimStruct> >

// TEMPLATE: LEGO1 0x1006a750
// _Tree<char const *,pair<char const * const,LegoAnimStruct>,map<char const *,LegoAnimStruct,LegoAnimStructComparator,allocator<LegoAnimStruct> >::_Kfn,LegoAnimStructComparator,allocator<LegoAnimStruct> >::iterator::_Dec

// TEMPLATE: LEGO1 0x1006a7a0
// _Tree<char const *,pair<char const * const,LegoAnimStruct>,map<char const *,LegoAnimStruct,LegoAnimStructComparator,allocator<LegoAnimStruct> >::_Kfn,LegoAnimStructComparator,allocator<LegoAnimStruct> >::_Insert

// TEMPLATE: LEGO1 0x1006c1b0
// _Tree<char const *,pair<char const * const,char const *>,map<char const *,char const *,LegoAnimSubstComparator,allocator<char const *> >::_Kfn,LegoAnimSubstComparator,allocator<char const *> >::iterator::_Dec

// TEMPLATE: LEGO1 0x1006c200
// _Tree<char const *,pair<char const * const,char const *>,map<char const *,char const *,LegoAnimSubstComparator,allocator<char const *> >::_Kfn,LegoAnimSubstComparator,allocator<char const *> >::_Insert

// TEMPLATE: LEGO1 0x1006c4b0
// list<char *,allocator<char *> >::~list<char *,allocator<char *> >

// TEMPLATE: LEGO1 0x1006c520
// List<char *>::~List<char *>

// GLOBAL: LEGO1 0x100f7680
// _Tree<char const *,pair<char const * const,char const *>,map<char const *,char const *,LegoAnimSubstComparator,allocator<char const *> >::_Kfn,LegoAnimSubstComparator,allocator<char const *> >::_Nil

// GLOBAL: LEGO1 0x100f7688
// _Tree<char const *,pair<char const * const,LegoAnimStruct>,map<char const *,LegoAnimStruct,LegoAnimStructComparator,allocator<LegoAnimStruct> >::_Kfn,LegoAnimStructComparator,allocator<LegoAnimStruct> >::_Nil
// clang-format on

#endif // LEGOANIMPRESENTER_H
