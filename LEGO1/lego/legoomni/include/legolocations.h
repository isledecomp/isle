#ifndef LEGOLOCATIONS_H
#define LEGOLOCATIONS_H

#include "decomp.h"
#include "mxtypes.h"

// SIZE 0x60
struct LegoLocation {
	// SIZE 0x18
	struct Boundary {
		const char* m_name; // 0x00
		MxS32 m_src;        // 0x04
		float m_srcScale;   // 0x08
		MxS32 m_dest;       // 0x0c
		float m_destScale;  // 0x10
		MxBool m_unk0x10;   // 0x14
	};

	MxU32 m_index;        // 0x00
	const char* m_name;   // 0x04
	float m_position[3];  // 0x08
	float m_direction[3]; // 0x14
	float m_up[3];        // 0x20
	Boundary m_boundaryA; // 0x2c
	Boundary m_boundaryB; // 0x44
	MxBool m_unk0x5c;     // 0x5c
	MxU8 m_frequency;     // 0x5d
};

extern LegoLocation g_locations[70];

#endif // LEGOLOCATIONS_H
