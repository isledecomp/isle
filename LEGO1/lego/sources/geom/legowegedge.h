#ifndef __LEGOWEGEDGE_H
#define __LEGOWEGEDGE_H

#include "decomp.h"
#include "legoweedge.h"
#include "mxgeometry/mxgeometry3d.h"

struct LegoPathStruct;

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
	struct Path {
		// FUNCTION: LEGO1 0x10048280
		// FUNCTION: BETA10 0x100bd450
		Path()
		{
			m_unk0x00 = NULL;
			m_unk0x04 = 0;
			m_unk0x08 = 0.0f;
		}

		LegoPathStruct* m_unk0x00; // 0x00
		undefined4 m_unk0x04;      // 0x04
		float m_unk0x08;           // 0x08
	};

	LegoWEGEdge();
	~LegoWEGEdge() override;

	LegoResult VTable0x04() override; // vtable+0x04

	inline LegoU32 GetFlag0x10() { return m_flags & c_bit5 ? FALSE : TRUE; }
	inline Mx4DPointFloat* GetUnknown0x14() { return &m_unk0x14; }
	inline Mx4DPointFloat* GetEdgeNormal(int index) { return &m_edgeNormals[index]; }
	inline LegoChar* GetName() { return m_name; }

	inline void SetFlag0x10(LegoU32 p_disable)
	{
		if (p_disable) {
			m_flags &= ~c_bit5;
		}
		else {
			m_flags |= c_bit5;
		}
	}

	inline LegoU8 GetMask0x03() { return m_flags & (c_bit1 | c_bit2); }

	// SYNTHETIC: LEGO1 0x1009a7e0
	// LegoWEGEdge::`scalar deleting destructor'

	friend class LegoPathController;

protected:
	LegoU8 m_flags;                // 0x0c
	LegoU8 m_unk0x0d;              // 0x0d
	LegoChar* m_name;              // 0x10
	Mx4DPointFloat m_unk0x14;      // 0x14
	Mx4DPointFloat* m_edgeNormals; // 0x2c
	Mx3DPointFloat m_unk0x30;      // 0x30
	LegoU32 m_unk0x44;             // 0x44
	LegoU8 m_unk0x48;              // 0x48
	Path* m_unk0x4c;               // 0x4c
	Mx3DPointFloat* m_unk0x50;     // 0x50
};

#endif // __LEGOWEGEDGE_H
