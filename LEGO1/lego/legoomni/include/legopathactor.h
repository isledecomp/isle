#ifndef LEGOPATHACTOR_H
#define LEGOPATHACTOR_H

#include "legoactor.h"
#include "legopathboundary.h"
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

	void ParseAction(char*) override;              // vtable+0x20
	virtual void VTable0x68();                     // vtable+0x68
	virtual void VTable0x6c();                     // vtable+0x6c
	virtual void VTable0x70(float p_float);        // vtable+0x70
	virtual void VTable0x74(Matrix4& p_transform); // vtable+0x74

	// FUNCTION: LEGO1 0x10002d20
	virtual void SetUserNavFlag(MxBool p_userNavFlag) { m_userNavFlag = p_userNavFlag; } // vtable+0x78

	// FUNCTION: LEGO1 0x10002d30
	virtual MxU8 GetUserNavFlag() { return m_userNavFlag; } // vtable+0x7c

	virtual void VTable0x80(); // vtable+0x80
	virtual void VTable0x84(); // vtable+0x84
	virtual void VTable0x88(); // vtable+0x88
	virtual void VTable0x8c(); // vtable+0x8c

	// FUNCTION: LEGO1 0x10002d40
	virtual MxS32 VTable0x90() { return 0; } // vtable+0x90

	// FUNCTION: LEGO1 0x10002d50
	virtual MxS32 VTable0x94() { return 0; } // vtable+0x94

	virtual void VTable0x98(); // vtable+0x98
	virtual void VTable0x9c(); // vtable+0x9c

	// FUNCTION: LEGO1 0x10002d60
	virtual MxS32 VTable0xa0() { return 0; } // vtable+0xa0

	virtual void VTable0xa4(); // vtable+0xa4
	virtual void VTable0xa8(); // vtable+0xa8

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
	inline LegoPathController* GetController() { return m_controller; }

	inline void SetBoundary(LegoPathBoundary* p_boundary) { m_boundary = p_boundary; }
	inline void SetUnknownDC(MxU32 p_unk0xdc) { m_unk0xdc = p_unk0xdc; }
	inline void ClearController() { m_controller = NULL; }

	// SYNTHETIC: LEGO1 0x1002d800
	// LegoPathActor::`scalar deleting destructor'

protected:
	MxFloat m_bADuration;             // 0x78
	undefined4 m_unk0x7c;             // 0x7c
	MxFloat m_unk0x80;                // 0x80
	MxFloat m_unk0x84;                // 0x84
	LegoPathBoundary* m_boundary;     // 0x88
	undefined m_unk0x8c[0x14];        // 0x8c
	MxFloat m_unk0xa0;                // 0xa0
	undefined m_unk0xa4[0x38];        // 0xa4
	MxU32 m_unk0xdc;                  // 0xdc
	undefined4 m_destEdge;            // 0xe0
	undefined4 m_unk0xe4;             // 0xe4
	undefined2 m_unk0xe8;             // 0xe8
	MxBool m_userNavFlag;             // 0xea
	MxMatrix m_unk0xec;               // 0xec
	undefined4 m_unk0x134;            // 0x134
	LegoPathController* m_controller; // 0x138
	MxFloat m_unk0x13c;               // 0x13c
	MxFloat m_unk0x140;               // 0x140
	MxFloat m_unk0x144;               // 0x144
	MxU8 m_unk0x148;                  // 0x148
	MxS32 m_unk0x14c;                 // 0x14c
	MxFloat m_unk0x150;               // 0x150
};

#endif // LEGOPATHACTOR_H
