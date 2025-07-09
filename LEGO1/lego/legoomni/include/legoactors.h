#ifndef LEGOACTORS_H
#define LEGOACTORS_H

#include "decomp.h"
#include "mxtypes.h"

class LegoExtraActor;
class LegoROI;

// SIZE 0x108
struct LegoActorInfo {
	// SIZE 0x18
	struct Part {
		MxU8* m_partNameIndices; // 0x00
		const char** m_partName; // 0x04
		MxU8 m_partNameIndex;    // 0x08
		MxU8* m_nameIndices;     // 0x0c
		const char** m_names;    // 0x10
		MxU8 m_nameIndex;        // 0x14
	};

	const char* m_name;      // 0x00
	LegoROI* m_roi;          // 0x04
	LegoExtraActor* m_actor; // 0x08
	MxS32 m_sound;           // 0x0c
	MxS32 m_move;            // 0x10
	MxU8 m_mood;             // 0x14
	Part m_parts[10];        // 0x18
};

// SIZE 0x58
struct LegoActorLOD {
	enum {
		c_useTexture = 0x01,
		c_useColor = 0x02
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

enum LegoActorLODs {
	c_topLOD,
	c_bodyLOD,
	c_infohatLOD,
	c_infogronLOD,
	c_headLOD,
	c_armlftLOD,
	c_armrtLOD,
	c_clawlftLOD,
	c_clawrtLOD,
	c_leglftLOD,
	c_legrtLOD
};

enum LegoActorParts {
	c_bodyPart,
	c_infohatPart,
	c_infogronPart,
	c_headPart,
	c_armlftPart,
	c_armrtPart,
	c_clawlftPart,
	c_clawrtPart,
	c_leglftPart,
	c_legrtPart
};

extern LegoActorInfo g_actorInfoInit[66];
extern LegoActorLOD g_actorLODs[11];

#endif // LEGOACTORS_H
