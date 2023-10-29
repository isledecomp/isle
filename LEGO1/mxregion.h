#ifndef MXREGION_H
#define MXREGION_H

#include "decomp.h"
#include "mxcore.h"
#include "mxrect32.h"

// VTABLE 0x100dcae8
// SIZE 0x1c
class MxRegion : public MxCore {
public:
	MxRegion();
	virtual ~MxRegion() override;

	virtual void Reset();
	virtual void vtable18(MxRect32& p_rect);
	virtual void vtable1c();
	virtual MxBool vtable20();

	inline MxRect32& GetRect() { return this->m_rect; }

private:
	// A container (probably MxList) holding MxRect32
	// MxList<MxRect32*> *m_rects;
	undefined4 m_unk08;
	MxRect32 m_rect;
};

#endif // MXREGION_H
