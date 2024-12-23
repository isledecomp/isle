#ifndef MXUTILITYLIST_H
#define MXUTILITYLIST_H

#include "mxstl/stlcompat.h"

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

	// Note: does not take a reference
	void PushBack(T p_obj) { this->push_back(p_obj); }
};

#endif // MXUTILITYLIST_H
