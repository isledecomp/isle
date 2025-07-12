#ifndef LEGOEXTRAACTOR_H
#define LEGOEXTRAACTOR_H

#include "legoanimactor.h"

// VTABLE: LEGO1 0x100d6c00 LegoAnimActor
// VTABLE: LEGO1 0x100d6c10 LegoPathActor
// VTABLE: LEGO1 0x100d6cdc LegoExtraActor
// VTABLE: BETA10 0x101bc2a0 LegoAnimActor
// VTABLE: BETA10 0x101bc2b8 LegoPathActor
// VTABLE: BETA10 0x101bc3a8 LegoExtraActor
// SIZE 0x1dc
class LegoExtraActor : public virtual LegoAnimActor {
public:
	enum Axis {
		e_posz,
		e_negz,
		e_posx,
		e_negx
	};

	LegoExtraActor();
	~LegoExtraActor() override;

	// FUNCTION: LEGO1 0x1002b7b0
	// FUNCTION: BETA10 0x100831a0
	const char* ClassName() const override // vtable+0x0c
	{
		// STRING: LEGO1 0x100f3204
		return "LegoExtraActor";
	}

	// FUNCTION: LEGO1 0x1002b7d0
	MxBool IsA(const char* p_name) const override // vtable+0x10
	{
		return !strcmp(p_name, LegoExtraActor::ClassName()) || LegoAnimActor::IsA(p_name);
	}

	void SetWorldSpeed(MxFloat p_worldSpeed) override; // vtable+0x30
	MxS32 CheckIntersections(Vector3& p_rayOrigin, Vector3& p_rayEnd, Vector3& p_intersectionPoint)
		override; // vtable+0x68
	inline MxU32 CheckPresenterAndActorIntersections(
		LegoPathBoundary* p_boundary,
		Vector3& p_rayOrigin,
		Vector3& p_rayDirection,
		float p_rayLength,
		float p_radius,
		Vector3& p_intersectionPoint
	) override;                                                                                    // vtable+0x6c
	void Animate(float p_time) override;                                                           // vtable+0x70
	void ApplyTransform(Matrix4& p_transform) override;                                            // vtable+0x74
	MxU32 StepState(float p_time, Matrix4& p_matrix) override;                                     // vtable+0x90
	MxResult HitActor(LegoPathActor* p_actor, MxBool p_bool) override;                             // vtable+0x94
	MxResult CalculateSpline() override;                                                           // vtable+0x9c
	void GetWalkingBehavior(MxBool& p_countCounterclockWise, MxS32& p_selectedEdgeIndex) override; // vtable+0xa4
	void VTable0xc4() override;                                                                    // vtable+0xc4

	virtual MxResult SwitchDirection();

	void Restart();
	inline void InitializeReassemblyAnim();

	void SetPathWalkingMode(MxU8 p_pathWalkingMode) { m_pathWalkingMode = p_pathWalkingMode; }

	// SYNTHETIC: LEGO1 0x1002b760
	// LegoExtraActor::`scalar deleting destructor'

private:
	enum {
		e_none = 0,
		e_disassemble = 1,
		e_assemble = 2,
	};

	MxFloat m_scheduledTime;             // 0x08
	MxU8 m_pathWalkingMode;              // 0x0c
	MxU8 m_axis;                         // 0x0d
	MxBool m_animationAtCurrentBoundary; // 0x0e
	MxFloat m_prevWorldSpeed;            // 0x10
	MxU8 m_reassemblyAnimation;          // 0x14
	MxU8 m_hitBlockCounter;              // 0x15
	MxMatrix m_localBeforeHit;           // 0x18
	LegoAnimActorStruct* m_assAnim;      // 0x60
	LegoAnimActorStruct* m_disAnim;      // 0x64
};

// GLOBAL: LEGO1 0x100d6be8
// LegoExtraActor::`vbtable'{for `LegoAnimActor'}

// GLOBAL: LEGO1 0x100d6bf0
// LegoExtraActor::`vbtable'{for `LegoExtraActor'}

// TEMPLATE: LEGO1 0x1002b200
// vector<unsigned char *,allocator<unsigned char *> >::vector<unsigned char *,allocator<unsigned char *> >

// TEMPLATE: LEGO1 0x1002b270
// vector<unsigned char *,allocator<unsigned char *> >::size

// TEMPLATE: LEGO1 0x1002b720
// ?uninitialized_copy@@YAPAPAEPAPAE00@Z

#endif // LEGOEXTRAACTOR_H
