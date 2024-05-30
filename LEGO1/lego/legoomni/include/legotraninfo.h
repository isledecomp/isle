#ifndef LEGOTRANINFO_H
#define LEGOTRANINFO_H

#include "decomp.h"
#include "mxgeometry/mxmatrix.h"
#include "mxtypes.h"

struct AnimInfo;
class LegoAnimMMPresenter;
class LegoROI;
class MxPresenter;

// SIZE 0x78
struct LegoTranInfo {
	enum {
		c_bit1 = 0x01,
		c_bit2 = 0x02
	};

	LegoTranInfo()
	{
		m_index = 0;
		m_unk0x08 = NULL;
		m_unk0x0c = NULL;
		m_unk0x10 = 0;
		m_location = -1;
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

	~LegoTranInfo() { delete m_unk0x0c; }

	AnimInfo* m_animInfo;             // 0x00
	MxU32 m_index;                    // 0x04
	LegoROI* m_unk0x08;               // 0x08
	MxMatrix* m_unk0x0c;              // 0x0c
	MxU8 m_unk0x10;                   // 0x10
	MxS16 m_location;                 // 0x12
	MxBool m_unk0x14;                 // 0x14
	MxBool m_unk0x15;                 // 0x15
	MxU32 m_objectId;                 // 0x18
	MxPresenter** m_unk0x1c;          // 0x1c
	MxLong* m_unk0x20;                // 0x20
	LegoAnimMMPresenter* m_presenter; // 0x24
	MxBool m_unk0x28;                 // 0x28
	MxBool m_unk0x29;                 // 0x29
	MxMatrix m_unk0x2c;               // 0x2c
	MxU32 m_flags;                    // 0x74
};

#endif // LEGOTRANINFO_H
