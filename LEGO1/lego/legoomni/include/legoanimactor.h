#ifndef LEGOANIMACTOR_H
#define LEGOANIMACTOR_H

#include "decomp.h"
#include "lego/sources/anim/legoanim.h"
#include "legopathactor.h"

// SIZE 0x20
struct LegoAnimActorStruct {
	LegoAnimActorStruct(float p_float, LegoAnim* p_animTreePtr, LegoROI** p_roiMap, MxU32 p_numROIs);
	~LegoAnimActorStruct();
	float GetDuration();
	float m_unk0x00;         // 0x00
	LegoAnim* m_animTreePtr; // 0x04
	LegoROI** m_roiMap;      // 0x08
	MxU32 m_numROIs;         // 0x0c
	vector<void*> m_unk0x10; // 0x10
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
	void VTable0x70(float p_float) override;           // vtable+0x70
	void VTable0x74(Matrix4& p_transform) override;    // vtable+0x74

	virtual MxResult FUN_1001c1f0(float& p_out);
	virtual MxResult FUN_1001c360(float, Matrix4& p_transform);
	virtual MxResult FUN_1001c450(LegoAnim* p_animTreePtr, float p_float, LegoROI** p_roiMap, MxU32 p_numROIs);
	virtual void ClearMaps();

	// SYNTHETIC: LEGO1 0x1000fb60
	// LegoAnimActor::`scalar deleting destructor'

private:
	vector<LegoAnimActorStruct*> m_animMaps; // 0x08
	MxS16 m_curAnim;                         // 0x18
};

// TEMPLATE: LEGO1 0x1000da60
// Vector<LegoAnimActorStruct *>::~Vector<LegoAnimActorStruct *>

// TEMPLATE: LEGO1 0x1001c010
// vector<void *,allocator<void *> >::~vector<void *,allocator<void *> >

// TEMPLATE: LEGO1 0x1001c050
// Vector<void *>::~Vector<void *>

// TEMPLATE: LEGO1 0x1001c7c0
// vector<LegoAnimActorStruct *,allocator<LegoAnimActorStruct *> >::size

// TEMPLATE: LEGO1 0x1001c7e0
// vector<LegoAnimActorStruct *,allocator<LegoAnimActorStruct *> >::_Destroy

// TEMPLATE: LEGO1 0x1001c9e0
// uninitialized_fill_n

// TEMPLATE: LEGO1 0x1001ca10
// uninitialized_copy

#endif // LEGOANIMACTOR_H
