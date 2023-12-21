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
	virtual ~MxRegion() override;

	virtual void Reset();
	virtual void VTable0x18(MxRect32& p_rect);
	virtual MxBool VTable0x1c(MxRect32& p_rect);
	virtual MxBool VTable0x20();

	inline MxRect32& GetRect() { return this->m_rect; }

private:
	MxRegionList* m_list;
	MxRect32 m_rect;
};

#endif // MXREGION_H
