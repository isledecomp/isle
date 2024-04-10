#ifndef __LEGOWEGEDGE_H
#define __LEGOWEGEDGE_H

#include "decomp.h"
#include "legoweedge.h"
#include "mxgeometry/mxgeometry3d.h"

// VTABLE: LEGO1 0x100db7f8
// SIZE 0x54
class LegoWEGEdge : public LegoWEEdge {
public:
	LegoWEGEdge();
	~LegoWEGEdge() override;

	LegoResult VTable0x04() override; // vtable+0x04

	inline LegoU32 GetFlag0x10() { return m_unk0x0c & 0x10 ? FALSE : TRUE; }
	inline Mx4DPointFloat* GetUnknown0x14() { return &m_unk0x14; }
	inline Mx4DPointFloat* GetEdgeNormal(int index) { return &m_edgeNormals[index]; }

	// SYNTHETIC: LEGO1 0x1009a7e0
	// LegoWEGEdge::`scalar deleting destructor'

private:
	LegoU8 m_unk0x0c;              // 0x0c
	LegoU8 m_unk0x0d;              // 0x0d
	LegoChar* m_name;              // 0x10
	Mx4DPointFloat m_unk0x14;      // 0x14
	Mx4DPointFloat* m_edgeNormals; // 0x2c
	Mx3DPointFloat m_unk0x30;      // 0x30
	LegoU32 m_unk0x44;             // 0x44
	LegoU8 m_unk0x48;              // 0x48
	undefined* m_unk0x4c;          // 0x4c
	undefined* m_unk0x50;          // 0x50
};

#endif // __LEGOWEGEDGE_H
