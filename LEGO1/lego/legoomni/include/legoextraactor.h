#ifndef LEGOEXTRAACTOR_H
#define LEGOEXTRAACTOR_H

#include "legoanimactor.h"

// VTABLE: LEGO1 0x100d6c00 LegoAnimActor
// VTABLE: LEGO1 0x100d6c10 LegoPathActor
// VTABLE: LEGO1 0x100d6cdc LegoExtraActor
// VTABLE: BETA10 0x101bc2b8 LegoPathActor
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

	void SetWorldSpeed(MxFloat p_worldSpeed) override;       // vtable+0x30
	MxS32 VTable0x68(Vector3&, Vector3&, Vector3&) override; // vtable+0x68
	MxU32 VTable0x6c(
		LegoPathBoundary* p_boundary,
		Vector3& p_v1,
		Vector3& p_v2,
		float p_f1,
		float p_f2,
		Vector3& p_v3
	) override;                                                        // vtable+0x6c
	void Animate(float p_time) override;                               // vtable+0x70
	void VTable0x74(Matrix4& p_transform) override;                    // vtable+0x74
	MxU32 VTable0x90(float p_time, Matrix4& p_matrix) override;        // vtable+0x90
	MxResult HitActor(LegoPathActor* p_actor, MxBool p_bool) override; // vtable+0x94
	MxResult VTable0x9c() override;                                    // vtable+0x9c
	void VTable0xa4(MxBool& p_und1, MxS32& p_und2) override;           // vtable+0xa4
	void VTable0xc4() override;                                        // vtable+0xc4

	virtual MxResult FUN_1002aae0();

	void Restart();
	inline void FUN_1002ad8a();

	void SetUnknown0x0c(undefined p_unk0x0c) { m_unk0x0c = p_unk0x0c; }

	// SYNTHETIC: LEGO1 0x1002b760
	// LegoExtraActor::`scalar deleting destructor'

private:
	MxFloat m_scheduledTime;        // 0x08
	undefined m_unk0x0c;            // 0x0c
	MxU8 m_axis;                    // 0x0d
	undefined m_unk0x0e;            // 0x0e
	MxFloat m_prevWorldSpeed;       // 0x10
	MxU8 m_whichAnim;               // 0x14
	MxU8 m_unk0x15;                 // 0x15
	MxMatrix m_unk0x18;             // 0x18
	LegoAnimActorStruct* m_assAnim; // 0x60
	LegoAnimActorStruct* m_disAnim; // 0x64
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
