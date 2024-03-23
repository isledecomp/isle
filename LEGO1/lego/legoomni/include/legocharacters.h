#ifndef LEGOCHARACTERS_H
#define LEGOCHARACTERS_H

#include "decomp.h"
#include "mxtypes.h"

class LegoExtraActor;
class LegoROI;

// SIZE 0x108
struct LegoCharacterData {
	// SIZE 0x18
	struct Part {
		MxU8* m_unk0x00;        // 0x00
		const char** m_unk0x04; // 0x04
		MxU8 m_unk0x08;         // 0x08
		MxU8* m_unk0x0c;        // 0x0c
		const char** m_unk0x10; // 0x10
		MxU8 m_unk0x14;         // 0x14
	};

	const char* m_name;      // 0x00
	LegoROI* m_roi;          // 0x04
	LegoExtraActor* m_actor; // 0x08
	MxS32 m_unk0x0c;         // 0x0c
	MxS32 m_unk0x10;         // 0x10
	MxU8 m_unk0x14;          // 0x14
	Part m_parts[10];        // 0x18
};

// SIZE 0x58
struct LegoCharacterLOD {
	enum {
		c_flag1 = 0x01,
		c_flag2 = 0x02
	};

	const char* m_name;        // 0x00
	const char* m_parentName;  // 0x04
	MxU32 m_flags;             // 0x08
	float m_boundingSphere[4]; // 0x0c
	float m_boundingBox[6];    // 0x1c
	float m_position[3];       // 0x34
	float m_direction[3];      // 0x40
	float m_up[3];             // 0x4c
};

extern LegoCharacterData g_characterDataInit[66];
extern LegoCharacterLOD g_characterLODs[11];

#endif // LEGOCHARACTERS_H
