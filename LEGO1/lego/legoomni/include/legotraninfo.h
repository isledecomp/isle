#ifndef LEGOTRANINFO_H
#define LEGOTRANINFO_H

#include "decomp.h"
#include "mxgeometry/mxmatrix.h"

class LegoAnimMMPresenter;

// SIZE 0x78
struct LegoTranInfo {
	enum {
		c_bit2 = 0x02
	};

	LegoTranInfo()
	{
		m_index = 0;
		m_unk0x08 = 0;
		m_unk0x0c = NULL;
		m_unk0x10 = FALSE;
		m_unk0x12 = -1;
		m_unk0x14 = FALSE;
		m_unk0x1c = NULL;
		m_unk0x20 = NULL;
		m_presenter = NULL;
		m_unk0x15 = TRUE;
		m_unk0x28 = TRUE;
		m_unk0x29 = TRUE;
		m_flags = 0;
		m_unk0x2c.SetIdentity();
	}

	undefined4 m_unk0x00;             // 0x00
	MxU32 m_index;                    // 0x04
	undefined4 m_unk0x08;             // 0x08
	MxMatrix* m_unk0x0c;              // 0x0c
	MxBool m_unk0x10;                 // 0x10
	MxS16 m_unk0x12;                  // 0x12
	MxBool m_unk0x14;                 // 0x14
	MxBool m_unk0x15;                 // 0x15
	MxU32 m_objectId;                 // 0x18
	undefined4* m_unk0x1c;            // 0x1c
	undefined4* m_unk0x20;            // 0x20
	LegoAnimMMPresenter* m_presenter; // 0x24
	MxBool m_unk0x28;                 // 0x28
	MxBool m_unk0x29;                 // 0x29
	MxMatrix m_unk0x2c;               // 0x2c
	MxU32 m_flags;                    // 0x74
};

#endif // LEGOTRANINFO_H
