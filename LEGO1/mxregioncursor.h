#ifndef MXREGIONCURSOR_H
#define MXREGIONCURSOR_H

#include "mxregion.h"

// VTABLE: LEGO1 0x100dcbb8
// SIZE 0x18
class MxRegionCursor : public MxCore {
public:
	MxRegionCursor(MxRegion* p_region);
	virtual ~MxRegionCursor() override;

	virtual MxRect32* VTable0x14(MxRect32& p_rect); // vtable+0x14
	virtual MxRect32* VTable0x18();                 // vtable+0x18
	virtual MxRect32* VTable0x1c(MxRect32& p_rect); // vtable+0x1c
	virtual MxRect32* VTable0x20();                 // vtable+0x20
	virtual MxRect32* VTable0x24(MxRect32& p_rect); // vtable+0x24
	virtual MxRect32* VTable0x28();                 // vtable+0x28
	virtual MxRect32* VTable0x2c(MxRect32& p_rect); // vtable+0x2c
	virtual MxRect32* VTable0x30();                 // vtable+0x30

	// FUNCTION: LEGO1 0x100c4070
	virtual MxRect32* GetRect() { return m_rect; } // vtable+0x34

	// FUNCTION: LEGO1 0x100c4080
	virtual MxBool HasRect() { return m_rect != NULL; } // vtable+0x38

	virtual void Reset(); // vtable+0x3c

private:
	void FUN_100c46c0(MxRegionLeftRightList& p_leftRightList);
	void UpdateRect(MxS32 p_left, MxS32 p_top, MxS32 p_right, MxS32 p_bottom);
	void FUN_100c4a20(MxRect32& p_rect);
	void FUN_100c4b50(MxRect32& p_rect);

	MxRegion* m_region;                             // 0x08
	MxRect32* m_rect;                               // 0x0c
	MxRegionTopBottomListCursor* m_topBottomCursor; // 0x10
	MxRegionLeftRightListCursor* m_leftRightCursor; // 0x14
};

// SYNTHETIC: LEGO1 0x100c4090
// MxRegionCursor::`scalar deleting destructor'

#endif // MXREGIONCURSOR_H
