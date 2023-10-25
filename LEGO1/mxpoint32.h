#ifndef MXPOINT32_H
#define MXPOINT32_H

#include "mxtypes.h"

class MxPoint32 {
public:
	MxPoint32() {}
	MxPoint32(MxS32 p_x, MxS32 p_y)
	{
		this->m_x = p_x;
		this->m_y = p_y;
	}

	MxS32 m_x;
	MxS32 m_y;
};

#endif // MXPOINT32_H
