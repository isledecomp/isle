#ifndef LEGOTRANINFOLIST_H
#define LEGOTRANINFOLIST_H

#include "legotraninfo.h"
#include "mxlist.h"
#include "mxtypes.h"

// VTABLE: LEGO1 0x100d8ca8
// class MxCollection<LegoTranInfo *>

// VTABLE: LEGO1 0x100d8cc0
// class MxList<LegoTranInfo *>

// VTABLE: LEGO1 0x100d8cd8
// class MxPtrList<LegoTranInfo>

// VTABLE: LEGO1 0x100d8c90
// SIZE 0x18
class LegoTranInfoList : public MxPtrList<LegoTranInfo> {
public:
	LegoTranInfoList() : MxPtrList<LegoTranInfo>(FALSE) {}
};

// VTABLE: LEGO1 0x100d8cf0
// class MxListCursor<LegoTranInfo *>

// VTABLE: LEGO1 0x100d8d08
// class MxPtrListCursor<LegoTranInfo>

// VTABLE: LEGO1 0x100d8d20
// VTABLE: BETA10 0x101bad70
// SIZE 0x10
class LegoTranInfoListCursor : public MxPtrListCursor<LegoTranInfo> {
public:
	// FUNCTION: BETA10 0x100496d0
	LegoTranInfoListCursor(LegoTranInfoList* p_list) : MxPtrListCursor<LegoTranInfo>(p_list) {}
};

// TEMPLATE: LEGO1 0x1005fdf0
// MxCollection<LegoTranInfo *>::Compare

// TEMPLATE: LEGO1 0x1005fe00
// MxCollection<LegoTranInfo *>::~MxCollection<LegoTranInfo *>

// TEMPLATE: LEGO1 0x1005fe50
// MxCollection<LegoTranInfo *>::Destroy

// TEMPLATE: LEGO1 0x1005fe60
// MxList<LegoTranInfo *>::~MxList<LegoTranInfo *>

// SYNTHETIC: LEGO1 0x1005fef0
// LegoTranInfoList::`scalar deleting destructor'

// TEMPLATE: LEGO1 0x1005ff60
// MxPtrList<LegoTranInfo>::~MxPtrList<LegoTranInfo>

// SYNTHETIC: LEGO1 0x1005ffb0
// MxCollection<LegoTranInfo *>::`scalar deleting destructor'

// SYNTHETIC: LEGO1 0x10060020
// MxList<LegoTranInfo *>::`scalar deleting destructor'

// SYNTHETIC: LEGO1 0x100600d0
// MxPtrList<LegoTranInfo>::`scalar deleting destructor'

// SYNTHETIC: LEGO1 0x100612f0
// SYNTHETIC: BETA10 0x100498c0
// LegoTranInfoListCursor::`scalar deleting destructor'

// SYNTHETIC: BETA10 0x10049770
// MxPtrListCursor<LegoTranInfo>::MxPtrListCursor<LegoTranInfo>

// FUNCTION: LEGO1 0x10061360
// FUNCTION: BETA10 0x10049910
// MxPtrListCursor<LegoTranInfo>::~MxPtrListCursor<LegoTranInfo>

// SYNTHETIC: LEGO1 0x100613b0
// MxListCursor<LegoTranInfo *>::`scalar deleting destructor'

// SYNTHETIC: LEGO1 0x10061420
// MxPtrListCursor<LegoTranInfo>::`scalar deleting destructor'

// FUNCTION: LEGO1 0x10061490
// MxListCursor<LegoTranInfo *>::~MxListCursor<LegoTranInfo *>

// FUNCTION: LEGO1 0x100614e0
// FUNCTION: BETA10 0x10049ab0
// LegoTranInfoListCursor::~LegoTranInfoListCursor

#endif // LEGOTRANINFOLIST_H
