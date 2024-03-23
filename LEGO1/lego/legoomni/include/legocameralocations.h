#ifndef LEGOCAMERALOCATIONS_H
#define LEGOCAMERALOCATIONS_H

#include "decomp.h"
#include "mxtypes.h"

// SIZE 0x60
struct LegoCameraLocation {
	MxU32 m_index;          // 0x00
	const char* m_name;     // 0x04
	float m_position[3];    // 0x08
	float m_direction[3];   // 0x14
	float m_up[3];          // 0x20
	const char* m_edgeName; // 0x2c
	undefined4 m_unk0x30;   // 0x30
	float m_unk0x34;        // 0x34
	undefined4 m_unk0x38;   // 0x38
	float m_unk0x3c;        // 0x3c
	undefined4 m_unk0x40;   // 0x40
	undefined4 m_unk0x44;   // 0x44
	undefined4 m_unk0x48;   // 0x48
	undefined4 m_unk0x4c;   // 0x4c
	undefined4 m_unk0x50;   // 0x50
	undefined4 m_unk0x54;   // 0x54
	undefined4 m_unk0x58;   // 0x58
	undefined4 m_unk0x5c;   // 0x5c
};

extern LegoCameraLocation g_cameraLocations[70];

#endif // LEGOCAMERALOCATIONS_H
