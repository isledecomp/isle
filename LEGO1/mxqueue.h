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
		MxBool hasNext = (m_first != NULL);
		if (m_first) {
			p_obj = m_first->GetValue();
			DeleteEntry(m_first);
		}

		return hasNext;
	}
};

#endif // MXQUEUE_H
