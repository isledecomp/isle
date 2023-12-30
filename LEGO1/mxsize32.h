#ifndef MXSIZE32_H
#define MXSIZE32_H

#include "mxtypes.h"

class MxSize32 {
public:
	MxSize32() {}
	MxSize32(MxS32 p_width, MxS32 p_height) { CopyFrom(p_width, p_height); }

	inline MxS32 GetWidth() const { return m_width; }
	inline MxS32 GetHeight() const { return m_height; }

private:
	inline void CopyFrom(MxS32 p_width, MxS32 p_height)
	{
		this->m_width = p_width;
		this->m_height = p_height;
	}

	MxS32 m_width;
	MxS32 m_height;
};

#endif // MXSIZE32_H
