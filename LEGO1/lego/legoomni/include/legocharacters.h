#ifndef LEGOCHARACTERS_H
#define LEGOCHARACTERS_H

#include "decomp.h"
#include "mxtypes.h"

class LegoActor;

// SIZE 0x108
struct LegoCharacterData {
	// SIZE 0x18
	struct Part {
		MxS8* m_unk0x00;        // 0x00
		const char** m_unk0x04; // 0x04
		undefined m_unk0x08;    // 0x08
		MxS8* m_unk0x0c;        // 0x0c
		const char** m_unk0x10; // 0x10
		undefined m_unk0x14;    // 0x14
	};

	char* m_name;       // 0x00
	void* m_unk0x04;    // 0x04
	LegoActor* m_actor; // 0x08
	MxS32 m_unk0x0c;    // 0x0c
	MxS32 m_unk0x10;    // 0x10
	MxU8 m_unk0x14;     // 0x14
	Part m_parts[10];   // 0x18
};

#endif // LEGOCHARACTERS_H
