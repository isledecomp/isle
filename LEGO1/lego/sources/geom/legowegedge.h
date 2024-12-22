#ifndef __LEGOWEGEDGE_H
#define __LEGOWEGEDGE_H

#include "decomp.h"
#include "legoweedge.h"
#include "mxgeometry/mxgeometry3d.h"

class LegoPathStruct;

// might be a struct with public members
// VTABLE: LEGO1 0x100db7f8
// SIZE 0x54
class LegoWEGEdge : public LegoWEEdge {
public:
	enum {
		c_bit1 = 0x01,
		c_bit2 = 0x02,
		c_bit3 = 0x04,
		c_bit5 = 0x10
	};

	// SIZE 0x0c
	struct PathWithTrigger {
		// FUNCTION: LEGO1 0x10048280
		// FUNCTION: BETA10 0x100bd450
		PathWithTrigger()
		{
			m_pathStruct = NULL;
			m_data = 0;
			m_unk0x08 = 0.0f;
		}

		LegoPathStruct* m_pathStruct; // 0x00
		unsigned int m_data;          // 0x04
		float m_unk0x08;              // 0x08
	};

	LegoWEGEdge();
	~LegoWEGEdge() override;

	LegoS32 VTable0x04() override; // vtable+0x04

	// FUNCTION: BETA10 0x100270c0
	LegoU32 GetFlag0x10() { return m_flags & c_bit5 ? FALSE : TRUE; }

	// TODO: Other BETA10 reference at 0x1001c9e0, not sure what is going on
	// FUNCTION: BETA10 0x1001ff80
	Mx4DPointFloat* GetUnknown0x14() { return &m_unk0x14; }

	// FUNCTION: BETA10 0x1001ca10
	Mx4DPointFloat* GetEdgeNormal(int index) { return &m_edgeNormals[index]; }

	// FUNCTION: BETA10 0x1001c9b0
	const LegoChar* GetName() { return m_name; }

	void SetFlag0x10(LegoU32 p_disable)
	{
		if (p_disable) {
			m_flags &= ~c_bit5;
		}
		else {
			m_flags |= c_bit5;
		}
	}

	// FUNCTION: BETA10 0x1004a980
	LegoU8 GetMask0x03() { return m_flags & (c_bit1 | c_bit2); }

	// SYNTHETIC: LEGO1 0x1009a7e0
	// LegoWEGEdge::`scalar deleting destructor'

	friend class LegoPathController;

protected:
	LegoS32 FUN_1009aea0();

	LegoU8 m_flags;                 // 0x0c
	LegoU8 m_unk0x0d;               // 0x0d
	LegoChar* m_name;               // 0x10
	Mx4DPointFloat m_unk0x14;       // 0x14
	Mx4DPointFloat* m_edgeNormals;  // 0x2c
	Mx3DPointFloat m_unk0x30;       // 0x30
	float m_unk0x44;                // 0x44
	LegoU8 m_numTriggers;           // 0x48
	PathWithTrigger* m_pathTrigger; // 0x4c
	Mx3DPointFloat* m_unk0x50;      // 0x50
};

#endif // __LEGOWEGEDGE_H
