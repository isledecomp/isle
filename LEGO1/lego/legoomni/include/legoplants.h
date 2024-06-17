#ifndef LEGOPLANTS_H
#define LEGOPLANTS_H

#include "decomp.h"
#include "mxtypes.h"

class LegoEntity;
class LegoPathBoundary;

// SIZE 0x54
struct LegoPlantInfo {
	enum {
		c_flag1 = 0x01,
		c_flag2 = 0x02,
		c_flag5 = 0x10,
		c_flag6 = 0x20,
		c_flag16 = 0x8000,
		c_flag17 = 0x10000
	};

	enum Variant {
		e_flower = 0,
		e_tree,
		e_bush,
		e_palm
	};

	enum Color {
		e_white = 0,
		e_black,
		e_yellow,
		e_red,
		e_green
	};

	LegoEntity* m_entity;         // 0x00
	MxU32 m_flags;                // 0x04
	Variant m_variant;            // 0x08
	MxU32 m_sound;                // 0x0c
	MxU32 m_move;                 // 0x10
	MxU8 m_mood;                  // 0x14
	MxU8 m_color;                 // 0x15 - see enum for possible values
	undefined m_unk0x16;          // 0x16
	undefined m_initialUnk0x16;   // 0x17  = initial value loaded to m_unk0x16
	const char* m_name;           // 0x18
	undefined4 m_unk0x1c;         // 0x1c
	float m_x;                    // 0x20
	float m_y;                    // 0x24
	float m_z;                    // 0x28
	LegoPathBoundary* m_boundary; // 0x2c
	float m_position[3];          // 0x30
	float m_direction[3];         // 0x3c
	float m_up[3];                // 0x48
};

extern LegoPlantInfo g_plantInfoInit[81];

#endif // LEGOPLANTS_H
