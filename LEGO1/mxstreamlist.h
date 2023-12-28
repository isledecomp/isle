#ifndef MXSTREAMLIST_H
#define MXSTREAMLIST_H

#include "mxdsstreamingaction.h"
#include "mxdssubscriber.h"
#include "mxnextactiondatastart.h"
#include "mxstl/stlcompat.h"

template <class T>
class MxStreamList : public list<T> {
public:
	MxBool PopFront(T& p_obj)
	{
		if (empty())
			return FALSE;

		p_obj = front();
		pop_front();
		return TRUE;
	}
};

// SIZE 0xc
class MxStreamListMxDSAction : public MxStreamList<MxDSAction*> {
public:
	MxDSAction* Find(MxDSAction* p_action, MxBool p_delete);

	// There chance this list actually holds MxDSStreamingListAction
	// instead of MxDSAction. Until then, we use this helper.
	MxBool PopFrontStreamingAction(MxDSStreamingAction*& p_obj)
	{
		if (empty())
			return FALSE;

		p_obj = (MxDSStreamingAction*) front();
		pop_front();
		return TRUE;
	}
};

// SIZE 0xc
class MxStreamListMxNextActionDataStart : public MxStreamList<MxNextActionDataStart*> {
public:
	MxNextActionDataStart* Find(MxU32 p_id, MxS16 p_value);
	MxNextActionDataStart* FindAndErase(MxU32 p_id, MxS16 p_value);
};

// SIZE 0xc
class MxStreamListMxDSSubscriber : public MxStreamList<MxDSSubscriber*> {
public:
	MxDSSubscriber* Find(MxDSObject* p_object);
};

#endif // MXSTREAMLIST_H
