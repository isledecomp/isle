#ifndef MXSTREAMLIST_H
#define MXSTREAMLIST_H

#include "mxdsaction.h"
#include "mxdssubscriber.h"
#include "mxnextactiondatastart.h"
#include "mxstl/stlcompat.h"

template <class T>
class MxStreamList : public list<T> {};

// SIZE 0xc
class MxStreamListMxDSAction : public MxStreamList<MxDSAction*> {
public:
	MxDSAction* Find(MxDSAction* p_action, MxBool p_delete);

	// Could move this to MxStreamList
	MxBool PopFront(MxDSAction*& p_obj)
	{
		if (!empty()) {
			p_obj = front();
			pop_front();
			return TRUE;
		}

		return FALSE;
	}
};

// SIZE 0xc
class MxStreamListMxNextActionDataStart : public MxStreamList<MxNextActionDataStart*> {
public:
	MxNextActionDataStart* Find(MxU32, MxS16);
};

// SIZE 0xc
class MxStreamListMxDSSubscriber : public MxStreamList<MxDSSubscriber*> {};

#endif // MXSTREAMLIST_H
