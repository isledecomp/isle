#ifndef MXUTILITYLIST_H
#define MXUTILITYLIST_H

#include "mxstl/mxstl.h"

// Probably should be defined somewhere else

template <class T>
class MxUtilityList : public list<T> {
public:
	MxBool PopFront(T& p_obj)
	{
		if (this->empty()) {
			return FALSE;
		}

		p_obj = this->front();
		this->pop_front();
		return TRUE;
	}
};

#endif // MXUTILITYLIST_H
