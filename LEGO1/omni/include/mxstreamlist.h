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
		if (this->empty()) {
			return FALSE;
		}

		p_obj = this->front();
		this->pop_front();
		return TRUE;
	}
};

// SIZE 0x0c
class MxStreamListMxDSAction : public MxStreamList<MxDSAction*> {
public:
	// FUNCTION: BETA10 0x10150e30
	MxDSAction* FindAndErase(MxDSAction* p_action) { return FindInternal(p_action, TRUE); }

	// FUNCTION: BETA10 0x10150fc0
	MxDSAction* Find(MxDSAction* p_action) { return FindInternal(p_action, FALSE); }

	// There chance this list actually holds MxDSStreamingListAction
	// instead of MxDSAction. Until then, we use this helper.
	MxBool PopFrontStreamingAction(MxDSStreamingAction*& p_obj)
	{
		if (empty()) {
			return FALSE;
		}

		p_obj = (MxDSStreamingAction*) front();
		pop_front();
		return TRUE;
	}

private:
	MxDSAction* FindInternal(MxDSAction* p_action, MxBool p_delete);
};

// SIZE 0x0c
class MxStreamListMxNextActionDataStart : public MxStreamList<MxNextActionDataStart*> {
public:
	MxNextActionDataStart* Find(MxU32 p_id, MxS16 p_value);
	MxNextActionDataStart* FindAndErase(MxU32 p_id, MxS16 p_value);
};

// SIZE 0x0c
class MxStreamListMxDSSubscriber : public MxStreamList<MxDSSubscriber*> {
public:
	MxDSSubscriber* Find(MxDSObject* p_object);
};

#endif // MXSTREAMLIST_H
