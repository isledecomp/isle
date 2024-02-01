#ifndef MXREGION_H
#define MXREGION_H

#include "decomp.h"
#include "mxcore.h"
#include "mxrect32.h"
#include "mxregionlist.h"

// VTABLE: LEGO1 0x100dcae8
// SIZE 0x1c
class MxRegion : public MxCore {
public:
	MxRegion();
	~MxRegion() override;

	virtual void Reset();                        // vtable+0x14
	virtual void VTable0x18(MxRect32& p_rect);   // vtable+0x18
	virtual MxBool VTable0x1c(MxRect32& p_rect); // vtable+0x1c
	virtual MxBool VTable0x20();                 // vtable+0x20

	inline MxRegionTopBottomList* GetTopBottomList() const { return m_list; }
	inline const MxRect32& GetRect() const { return m_rect; }

	friend class MxRegionCursor;

	// SYNTHETIC: LEGO1 0x100c3670
	// MxRegion::`scalar deleting destructor'

private:
	MxRegionTopBottomList* m_list; // 0x08
	MxRect32 m_rect;               // 0x0c
};

#endif // MXREGION_H
