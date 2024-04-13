#ifndef LEGOPATHACTOR_H
#define LEGOPATHACTOR_H

#include "geom/legounkown100db7f4.h"
#include "legoactor.h"
#include "legopathboundary.h"
#include "misc/legounknown.h"
#include "mxtypes.h"
#include "realtime/matrix.h"

class LegoPathController;

// VTABLE: LEGO1 0x100d6e28
// SIZE 0x154
class LegoPathActor : public LegoActor {
public:
	LegoPathActor();
	~LegoPathActor() override;

	// FUNCTION: LEGO1 0x1000c430
	inline const char* ClassName() const override // vtable+0x0c
	{
		// STRING: LEGO1 0x100f0114
		return "LegoPathActor";
	}

	// FUNCTION: LEGO1 0x1000c440
	inline MxBool IsA(const char* p_name) const override // vtable+0x10
	{
		return !strcmp(p_name, LegoPathActor::ClassName()) || LegoActor::IsA(p_name);
	}

	void ParseAction(char* p_extra) override;                                   // vtable+0x20
	virtual void VTable0x68(Mx3DPointFloat&, Mx3DPointFloat&, Mx3DPointFloat&); // vtable+0x68
	virtual void VTable0x6c();                                                  // vtable+0x6c
	virtual void VTable0x70(float p_float);                                     // vtable+0x70
	virtual void VTable0x74(Matrix4& p_transform);                              // vtable+0x74

	// FUNCTION: LEGO1 0x10002d20
	virtual void SetUserNavFlag(MxBool p_userNavFlag) { m_userNavFlag = p_userNavFlag; } // vtable+0x78

	// FUNCTION: LEGO1 0x10002d30
	virtual MxU8 GetUserNavFlag() { return m_userNavFlag; } // vtable+0x7c

	virtual MxResult VTable0x80(
		Vector3& p_point1,
		Vector3& p_point2,
		Vector3& p_point3,
		Vector3& p_point4
	); // vtable+0x80
	virtual MxResult VTable0x84(
		LegoPathBoundary* p_boundary,
		float p_time,
		Vector3& p_p1,
		Vector3& p_p4,
		LegoUnknown100db7f4& p_destEdge,
		float p_destScale
	); // vtable+0x84
	virtual MxResult VTable0x88(
		LegoPathBoundary* p_boundary,
		float p_time,
		LegoEdge& p_srcEdge,
		float p_srcScale,
		LegoUnknown100db7f4& p_destEdge,
		float p_destScale
	);                         // vtable+0x88
	virtual void VTable0x8c(); // vtable+0x8c

	// FUNCTION: LEGO1 0x10002d40
	virtual MxU32 VTable0x90(float, Matrix4&) { return FALSE; } // vtable+0x90

	// FUNCTION: LEGO1 0x10002d50
	virtual MxResult VTable0x94(LegoPathActor*, MxBool) { return 0; } // vtable+0x94

	virtual void VTable0x98();           // vtable+0x98
	virtual MxResult WaitForAnimation(); // vtable+0x9c

	// FUNCTION: LEGO1 0x10002d60
	virtual MxS32 VTable0xa0() { return 0; } // vtable+0xa0

	virtual void VTable0xa4(MxU8&, MxS32&); // vtable+0xa4
	virtual void VTable0xa8();              // vtable+0xa8

	// FUNCTION: LEGO1 0x10002d70
	virtual void VTable0xac(MxFloat p_unk0x13c) { m_unk0x13c = p_unk0x13c; } // vtable+0xac

	// FUNCTION: LEGO1 0x10002d80
	virtual MxFloat VTable0xb0() { return m_unk0x13c; } // vtable+0xb0

	// FUNCTION: LEGO1 0x10002d90
	virtual MxFloat VTable0xb4() { return m_unk0x140; } // vtable+0xb4

	// FUNCTION: LEGO1 0x10002da0
	virtual MxFloat VTable0xb8() { return m_unk0x144; } // vtable+0xb8

	// FUNCTION: LEGO1 0x10002db0
	virtual void VTable0xbc(MxFloat p_unk0x140) { m_unk0x140 = p_unk0x140; } // vtable+0xbc

	// FUNCTION: LEGO1 0x10002dc0
	virtual void VTable0xc0(MxFloat p_unk0x144) { m_unk0x144 = p_unk0x144; } // vtable+0xc0

	// FUNCTION: LEGO1 0x10002dd0
	virtual void VTable0xc4() {} // vtable+0xc4

	// FUNCTION: LEGO1 0x10002de0
	virtual void VTable0xc8(MxU8 p_unk0x148) { m_unk0x148 = p_unk0x148; } // vtable+0xc8

	inline LegoPathBoundary* GetBoundary() { return m_boundary; }
	inline MxU32 GetState() { return m_state; }
	inline LegoPathController* GetController() { return m_controller; }

	inline void SetBoundary(LegoPathBoundary* p_boundary) { m_boundary = p_boundary; }
	inline void SetState(MxU32 p_state) { m_state = p_state; }
	inline void ClearController() { m_controller = NULL; }

	// SYNTHETIC: LEGO1 0x1002d800
	// LegoPathActor::`scalar deleting destructor'

protected:
	MxFloat m_BADuration;             // 0x78
	undefined4 m_unk0x7c;             // 0x7c
	MxFloat m_actorTime;              // 0x80
	MxFloat m_lastTime;               // 0x84
	LegoPathBoundary* m_boundary;     // 0x88
	LegoUnknown m_unk0x8c;            // 0x8c
	MxU32 m_state;                    // 0xdc
	LegoEdge* m_destEdge;             // 0xe0
	MxFloat m_unk0xe4;                // 0xe4
	undefined m_unk0xe8;              // 0xe8
	undefined m_unk0xe9;              // 0xe9
	MxBool m_userNavFlag;             // 0xea
	MxMatrix m_unk0xec;               // 0xec
	undefined* m_unk0x134;            // 0x134
	LegoPathController* m_controller; // 0x138
	MxFloat m_unk0x13c;               // 0x13c
	MxFloat m_unk0x140;               // 0x140
	MxFloat m_unk0x144;               // 0x144
	MxU8 m_unk0x148;                  // 0x148
	MxS32 m_unk0x14c;                 // 0x14c
	MxFloat m_unk0x150;               // 0x150
};

#endif // LEGOPATHACTOR_H
