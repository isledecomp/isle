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
	MxNotificationPtrList* m_postNotificationQueue; // 0x08
	MxNotificationPtrList* m_flashQueue;            // 0x0c
	MxCriticalSection m_lock;                       // 0x10
	MxS32 m_unk0x2c;                                // 0x2c
	MxIdList m_listenerIds;                         // 0x30
	MxBool m_active;                                // 0x3c

public:
	MxNotificationManager();
	~MxNotificationManager() override; // vtable+0x00 (scalar deleting destructor)

	MxResult Tickle() override; // vtable+0x08

	virtual MxResult Create(MxU32 p_frequencyMS, MxBool p_createThread); // vtable+0x14
	void Register(MxCore* p_listener);
	void Unregister(MxCore* p_listener);
	MxResult Send(MxCore* p_listener, const MxNotificationParam& p_param);

	MxNotificationPtrList* GetQueue() { return m_postNotificationQueue; }

	// FUNCTION: BETA10 0x10132270
	void SetActive(MxBool p_active) { m_active = p_active; }

	// FUNCTION: BETA10 0x10132230
	MxBool IsEmpty() const { return m_postNotificationQueue ? m_postNotificationQueue->empty() : TRUE; }

	// SYNTHETIC: LEGO1 0x100ac390
	// MxNotificationManager::`scalar deleting destructor'

private:
	void FlushPending(MxCore* p_object);
};

// TEMPLATE: LEGO1 0x100ac320 SYMBOL
// ??1?$list@IV?$allocator@I@@@@QAE@XZ

// FUNCTION: LEGO1 0x100ac3b0
// MxIdList::~MxIdList

// TEMPLATE: LEGO1 0x100ac400
// List<unsigned int>::~List<unsigned int>

// TEMPLATE: LEGO1 0x100ac540
// List<MxNotification *>::~List<MxNotification *>

// TEMPLATE: LEGO1 0x100ac590 SYMBOL
// ??1?$list@PAVMxNotification@@V?$allocator@PAVMxNotification@@@@@@QAE@XZ

// TEMPLATE: LEGO1 0x100acbf0 SYMBOL
// ?begin@?$list@PAVMxNotification@@V?$allocator@PAVMxNotification@@@@@@QAE?AViterator@1@XZ

// TEMPLATE: LEGO1 0x100acc00 SYMBOL
// ?insert@?$list@PAVMxNotification@@V?$allocator@PAVMxNotification@@@@@@QAE?AViterator@1@V21@ABQAVMxNotification@@@Z

// TEMPLATE: LEGO1 0x100acc50 SYMBOL
// ?erase@?$list@PAVMxNotification@@V?$allocator@PAVMxNotification@@@@@@QAE?AViterator@1@V21@@Z

// TEMPLATE: LEGO1 0x100acca0 SYMBOL
// ?_Buynode@?$list@PAVMxNotification@@V?$allocator@PAVMxNotification@@@@@@IAEPAU_Node@1@PAU21@0@Z

// SYNTHETIC: LEGO1 0x100accd0
// MxNotificationPtrList::~MxNotificationPtrList

// TEMPLATE: BETA10 0x10129670
// list<MxNotification *,allocator<MxNotification *> >::empty

#endif // MXNOTIFICATIONMANAGER_H
