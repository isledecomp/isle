#ifndef LEGOCAMERALOCATIONS_H
#define LEGOCAMERALOCATIONS_H

#include "decomp.h"
#include "mxtypes.h"

// SIZE 0x60
struct LegoCameraLocation {
	// SIZE 0x18
	struct Path {
		const char* m_name;   // 0x00
		MxS32 m_src;          // 0x04
		float m_srcScale;     // 0x08
		MxS32 m_dest;         // 0x0c
		float m_destScale;    // 0x10
		undefined4 m_unk0x10; // 0x14
	};

	MxU32 m_index;        // 0x00
	const char* m_name;   // 0x04
	float m_position[3];  // 0x08
	float m_direction[3]; // 0x14
	float m_up[3];        // 0x20
	Path m_pathA;         // 0x2c
	Path m_pathB;         // 0x44
	undefined4 m_unk0x5c; // 0x5c
};

extern LegoCameraLocation g_cameraLocations[70];

#endif // LEGOCAMERALOCATIONS_H
