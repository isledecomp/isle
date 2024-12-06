#ifndef MXNOTIFICATIONMANAGER_H
#define MXNOTIFICATIONMANAGER_H

#include "mxcore.h"
#include "mxcriticalsection.h"
#include "mxstl/stlcompat.h"
#include "mxtypes.h"

class MxNotificationParam;

class MxNotification {
public:
	MxNotification(MxCore* p_target, const MxNotificationParam& p_param);
	~MxNotification();

	MxCore* GetTarget() { return m_target; }
	MxNotificationParam* GetParam() { return m_param; }

private:
	MxCore* m_target;             // 0x00
	MxNotificationParam* m_param; // 0x04
};

class MxIdList : public list<MxU32> {};

class MxNotificationPtrList : public list<MxNotification*> {};

// VTABLE: LEGO1 0x100dc078
class MxNotificationManager : public MxCore {
private:
	MxNotificationPtrList* m_queue;    // 0x08
	MxNotificationPtrList* m_sendList; // 0x0c
	MxCriticalSection m_lock;          // 0x10
	MxS32 m_unk0x2c;                   // 0x2c
	MxIdList m_listenerIds;            // 0x30
	MxBool m_active;                   // 0x3c

public:
	MxNotificationManager();
	~MxNotificationManager() override; // vtable+0x00 (scalar deleting destructor)

	MxResult Tickle() override; // vtable+0x08

	virtual MxResult Create(MxU32 p_frequencyMS, MxBool p_createThread); // vtable+0x14
	void Register(MxCore* p_listener);
	void Unregister(MxCore* p_listener);
	MxResult Send(MxCore* p_listener, const MxNotificationParam& p_param);

	MxNotificationPtrList* GetQueue() { return m_queue; }

	// FUNCTION: BETA10 0x10132270
	void SetActive(MxBool p_active) { m_active = p_active; }

	// FUNCTION: BETA10 0x10132230
	MxBool IsEmpty() const { return m_queue ? m_queue->empty() : TRUE; }

	// SYNTHETIC: LEGO1 0x100ac390
	// MxNotificationManager::`scalar deleting destructor'

private:
	void FlushPending(MxCore* p_listener);
};

// TEMPLATE: LEGO1 0x100ac320
// list<unsigned int,allocator<unsigned int> >::~list<unsigned int,allocator<unsigned int> >

// FUNCTION: LEGO1 0x100ac3b0
// MxIdList::~MxIdList

// TEMPLATE: LEGO1 0x100ac400
// List<unsigned int>::~List<unsigned int>

// TEMPLATE: LEGO1 0x100ac540
// List<MxNotification *>::~List<MxNotification *>

// TEMPLATE: LEGO1 0x100ac590
// list<MxNotification *,allocator<MxNotification *> >::~list<MxNotification *,allocator<MxNotification *> >

// TEMPLATE: LEGO1 0x100acbf0
// list<MxNotification *,allocator<MxNotification *> >::begin

// TEMPLATE: LEGO1 0x100acc00
// list<MxNotification *,allocator<MxNotification *> >::insert

// TEMPLATE: LEGO1 0x100acc50
// list<MxNotification *,allocator<MxNotification *> >::erase

// TEMPLATE: LEGO1 0x100acca0
// list<MxNotification *,allocator<MxNotification *> >::_Buynode

// SYNTHETIC: LEGO1 0x100accd0
// MxNotificationPtrList::~MxNotificationPtrList

// TEMPLATE: BETA10 0x10129670
// list<MxNotification *,allocator<MxNotification *> >::empty

#endif // MXNOTIFICATIONMANAGER_H
