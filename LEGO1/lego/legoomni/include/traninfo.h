#ifndef TRANINFO_H
#define TRANINFO_H

#include "mxlist.h"
#include "mxtypes.h"

// SIZE 0x78
struct TranInfo {              // See FUN_100609f0 for construction
	undefined m_unk0x00[0x78]; // 0x00
};

// VTABLE: LEGO1 0x100d8c90
// SIZE 0x18
class TranInfoList : public MxPtrList<TranInfo> {
public:
	TranInfoList(MxBool p_ownership = FALSE) : MxPtrList<TranInfo>(p_ownership) {}
};

// VTABLE: LEGO1 0x100d8ca8
// class MxCollection<TranInfo *>

// VTABLE: LEGO1 0x100d8cc0
// class MxList<TranInfo *>

// VTABLE: LEGO1 0x100d8cd8
// class MxPtrList<TranInfo>

// VTABLE: LEGO1 0x100d8cf0
// class MxListCursor<TranInfo *>

// VTABLE: LEGO1 0x100d8d08
// class MxPtrListCursor<TranInfo>

// VTABLE: LEGO1 0x100d8d20
// SIZE 0x10
class TranInfoListCursor : public MxPtrListCursor<TranInfo> {
public:
	TranInfoListCursor(TranInfoList* p_list) : MxPtrListCursor<TranInfo>(p_list) {}
};

// TEMPLATE: LEGO1 0x1005fdf0
// MxCollection<TranInfo *>::Compare

// TEMPLATE: LEGO1 0x1005fe50
// MxCollection<TranInfo *>::Destroy

// SYNTHETIC: LEGO1 0x1005fef0
// TranInfoList::`scalar deleting destructor'

// SYNTHETIC: LEGO1 0x1005ffb0
// MxCollection<TranInfo *>::`scalar deleting destructor'

// SYNTHETIC: LEGO1 0x10060020
// MxList<TranInfo *>::`scalar deleting destructor'

// SYNTHETIC: LEGO1 0x100600d0
// MxPtrList<TranInfo>::`scalar deleting destructor'

// SYNTHETIC: LEGO1 0x100612f0
// TranInfoListCursor::`scalar deleting destructor'

// SYNTHETIC: LEGO1 0x10061360
// MxPtrListCursor<TranInfo>::~MxPtrListCursor<TranInfo>

// SYNTHETIC: LEGO1 0x100613b0
// MxListCursor<TranInfo *>::`scalar deleting destructor'

// SYNTHETIC: LEGO1 0x10061420
// MxPtrListCursor<TranInfo>::`scalar deleting destructor'

// TEMPLATE: LEGO1 0x10061490
// MxListCursor<TranInfo *>::~MxListCursor<TranInfo *>

// TEMPLATE: LEGO1 0x100614e0
// TranInfoListCursor::~TranInfoListCursor

#endif // TranInfoLIST_H
