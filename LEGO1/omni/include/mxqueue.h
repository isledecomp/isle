#ifndef MXQUEUE_H
#define MXQUEUE_H

#include "mxlist.h"

template <class T>
class MxQueue : public MxList<T> {
public:
	void Enqueue(T& p_obj)
	{
		// TODO
	}

	MxBool Dequeue(T& p_obj)
	{
		MxBool hasNext = (this->m_first != NULL);
		if (this->m_first) {
			p_obj = this->m_first->GetValue();
			this->DeleteEntry(this->m_first);
		}

		return hasNext;
	}
};

#endif // MXQUEUE_H
