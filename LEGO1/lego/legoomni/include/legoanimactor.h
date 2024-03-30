#ifndef LEGOANIMACTOR_H
#define LEGOANIMACTOR_H

#include "anim/legoanim.h"
#include "decomp.h"
#include "legopathactor.h"

// SIZE 0x20
struct LegoAnimActorStruct {
	LegoAnimActorStruct(float p_unk0x00, LegoAnim* p_AnimTreePtr, LegoROI** p_roiMap, MxU32 p_numROIs);
	~LegoAnimActorStruct();

	float GetDuration();

	inline float GetUnknown0x00() { return m_unk0x00; }

	float m_unk0x00;              // 0x00
	LegoAnim* m_AnimTreePtr;      // 0x04
	LegoROI** m_roiMap;           // 0x08
	MxU32 m_numROIs;              // 0x0c
	vector<undefined*> m_unk0x10; // 0x10
};

// VTABLE: LEGO1 0x100d5440 LegoPathActor
// VTABLE: LEGO1 0x100d5510 LegoAnimActor
// SIZE 0x174
class LegoAnimActor : public virtual LegoPathActor {
public:
	LegoAnimActor() { m_curAnim = -1; }
	~LegoAnimActor() override;

	// FUNCTION: LEGO1 0x1000fba0
	inline const char* ClassName() const override // vtable+0x0c
	{
		// STRING: LEGO1 0x100f057c
		return "LegoAnimActor";
	}

	// FUNCTION: LEGO1 0x1000fbc0
	inline MxBool IsA(const char* p_name) const override // vtable+0x10
	{
		return !strcmp(p_name, LegoAnimActor::ClassName()) || LegoPathActor::IsA(p_name);
	}

	void ParseAction(char* p_extra) override;          // vtable+0x20
	void SetWorldSpeed(MxFloat p_worldSpeed) override; // vtable+0x30
	void VTable0x70(float p_und) override;             // vtable+0x70
	void VTable0x74(Matrix4& p_transform) override;    // vtable+0x74

	virtual MxResult FUN_1001c1f0(float& p_und);
	virtual MxResult FUN_1001c360(float, Matrix4& p_transform);
	virtual MxResult FUN_1001c450(LegoAnim* p_AnimTreePtr, float p_unk0x00, LegoROI** p_roiMap, MxU32 p_numROIs);
	virtual void ClearMaps();

	// SYNTHETIC: LEGO1 0x1000fb60
	// LegoAnimActor::`scalar deleting destructor'

protected:
	vector<LegoAnimActorStruct*> m_animMaps; // 0x08
	MxS16 m_curAnim;                         // 0x18
};

// clang-format off
// TEMPLATE: LEGO1 0x1000da20
// vector<LegoAnimActorStruct *,allocator<LegoAnimActorStruct *> >::~vector<LegoAnimActorStruct *,allocator<LegoAnimActorStruct *> >

// TEMPLATE: LEGO1 0x1000da60
// Vector<LegoAnimActorStruct *>::~Vector<LegoAnimActorStruct *>

// SYNTHETIC: LEGO1 0x10012b90
// LegoAnimActor::`vbase destructor'

// TEMPLATE: LEGO1 0x1001c010
// vector<unsigned char *,allocator<unsigned char *> >::~vector<unsigned char *,allocator<unsigned char *> >

// TEMPLATE: LEGO1 0x1001c050
// Vector<unsigned char *>::~Vector<unsigned char *>

// TEMPLATE: LEGO1 0x1001c7c0
// vector<LegoAnimActorStruct *,allocator<LegoAnimActorStruct *> >::size

// TEMPLATE: LEGO1 0x1001c7e0
// vector<LegoAnimActorStruct *,allocator<LegoAnimActorStruct *> >::_Destroy

// TEMPLATE: LEGO1 0x1001c9e0
// uninitialized_fill_n

// TEMPLATE: LEGO1 0x1001ca10
// uninitialized_copy
// clang-format on

#endif // LEGOANIMACTOR_H
