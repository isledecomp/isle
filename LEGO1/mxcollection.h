#ifndef MXCOLLECTION_H
#define MXCOLLECTION_H

#include "mxcore.h"

template <class T>
class MxCollection : public MxCore {
public:
	MxCollection()
	{
		m_count = 0;
		m_customDestructor = Destroy;
	}

	virtual ~MxCollection() {}

	static void Destroy(T){};
	virtual MxS8 Compare(T, T) { return 0; }

protected:
	MxU32 m_count;                 // 0x8
	void (*m_customDestructor)(T); // 0xc
};

#endif // MXCOLLECTION_H
