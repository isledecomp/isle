#ifndef LEGOANIMACTOR_H
#define LEGOANIMACTOR_H

#include "decomp.h"
#include "legopathactor.h"

class LegoAnim;

// SIZE 0x20
struct LegoAnimActorStruct {
	LegoAnimActorStruct(float p_unk0x00, LegoAnim* p_AnimTreePtr, LegoROI** p_roiMap, MxU32 p_numROIs);
	~LegoAnimActorStruct();

	float GetDuration();

	// FUNCTION: BETA10 0x1000fb10
	float GetUnknown0x00() { return m_unk0x00; }

	// FUNCTION: BETA10 0x10012210
	LegoAnim* GetAnimTreePtr() { return m_AnimTreePtr; }

	// FUNCTION: BETA10 0x10012240
	LegoROI** GetROIMap() { return m_roiMap; }

	// TODO: Possibly private
	float m_unk0x00;              // 0x00
	LegoAnim* m_AnimTreePtr;      // 0x04
	LegoROI** m_roiMap;           // 0x08
	MxU32 m_numROIs;              // 0x0c
	vector<undefined*> m_unk0x10; // 0x10
};

// VTABLE: LEGO1 0x100d5440 LegoPathActor
// VTABLE: LEGO1 0x100d5510 LegoAnimActor
// VTABLE: BETA10 0x101b81d8 LegoPathActor
// VTABLE: BETA10 0x101b82c8 LegoAnimActor
// SIZE 0x174
class LegoAnimActor : public virtual LegoPathActor {
public:
	// FUNCTION: BETA10 0x1000f6c0
	LegoAnimActor() { m_curAnim = -1; }

	~LegoAnimActor() override;

	// FUNCTION: LEGO1 0x1000fba0
	// FUNCTION: BETA10 0x10012400
	const char* ClassName() const override // vtable+0x0c
	{
		// STRING: LEGO1 0x100f057c
		return "LegoAnimActor";
	}

	// FUNCTION: LEGO1 0x1000fbc0
	// FUNCTION: BETA10 0x10012440
	MxBool IsA(const char* p_name) const override // vtable+0x10
	{
		return !strcmp(p_name, LegoAnimActor::ClassName()) || LegoPathActor::IsA(p_name);
	}

	void ParseAction(char* p_extra) override;          // vtable+0x20
	void SetWorldSpeed(MxFloat p_worldSpeed) override; // vtable+0x30
	void Animate(float p_time) override;               // vtable+0x70
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
// GLOBAL: LEGO1 0x100d5438
// LegoAnimActor::`vbtable'

// TEMPLATE: LEGO1 0x1000da20
// vector<LegoAnimActorStruct *,allocator<LegoAnimActorStruct *> >::~vector<LegoAnimActorStruct *,allocator<LegoAnimActorStruct *> >

// TEMPLATE: LEGO1 0x1000da60
// Vector<LegoAnimActorStruct *>::~Vector<LegoAnimActorStruct *>

// SYNTHETIC: LEGO1 0x10012b90
// SYNTHETIC: BETA10 0x1000fad0
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
// ?uninitialized_copy@@YAPAPAULegoAnimActorStruct@@PAPAU1@00@Z
// clang-format on

#endif // LEGOANIMACTOR_H
