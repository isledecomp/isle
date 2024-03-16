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

#endif // LEGOTRANINFOLIST_H
