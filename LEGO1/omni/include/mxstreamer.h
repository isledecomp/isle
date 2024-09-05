#ifndef MXSTREAMER_H
#define MXSTREAMER_H

#include "decomp.h"
#include "mxcore.h"
#include "mxmemorypool.h"
#include "mxnotificationparam.h"
#include "mxstl/stlcompat.h"
#include "mxstreamcontroller.h"
#include "mxtypes.h"

#include <assert.h>

class MxDSObject;

typedef MxMemoryPool<64, 22> MxMemoryPool64;
typedef MxMemoryPool<128, 2> MxMemoryPool128;

// VTABLE: LEGO1 0x100dc760
// VTABLE: BETA10 0x101c23c8
// SIZE 0x10
class MxStreamerNotification : public MxNotificationParam {
public:
	// FUNCTION: BETA10 0x10146e40
	MxStreamerNotification(NotificationId p_type, MxCore* p_sender, MxStreamController* p_ctrlr)
		: MxNotificationParam(p_type, p_sender)
	{
		m_controller = p_ctrlr;
	}

	MxNotificationParam* Clone() const override;

	// FUNCTION: BETA10 0x10147190
	MxStreamController* GetController() { return m_controller; }

private:
	MxStreamController* m_controller; // 0x0c
};

// VTABLE: LEGO1 0x100dc710
// VTABLE: BETA10 0x101c2378
// SIZE 0x2c
class MxStreamer : public MxCore {
public:
	enum OpenMode {
		e_diskStream = 0,
		e_RAMStream
	};

	MxStreamer();
	~MxStreamer() override; // vtable+0x00

	MxStreamController* Open(const char* p_name, MxU16 p_openMode);
	MxLong Close(const char* p_name);

	MxLong Notify(MxParam& p_param) override; // vtable+0x04

	// FUNCTION: LEGO1 0x100b9000
	// FUNCTION: BETA10 0x10145ee0
	const char* ClassName() const override // vtable+0x0c
	{
		// STRING: LEGO1 0x1010210c
		return "MxStreamer";
	}

	// FUNCTION: LEGO1 0x100b9010
	// FUNCTION: BETA10 0x10145f00
	MxBool IsA(const char* p_name) const override // vtable+0x10
	{
		return !strcmp(p_name, MxStreamer::ClassName()) || MxCore::IsA(p_name);
	}

	virtual MxResult Create(); // vtable+0x14

	MxBool FUN_100b9b30(MxDSObject& p_dsObject);
	MxStreamController* GetOpenStream(const char* p_name);
	void FUN_100b98f0(MxDSAction* p_action);
	MxResult AddStreamControllerToOpenList(MxStreamController* p_stream);
	MxResult FUN_100b99b0(MxDSAction* p_action);
	MxResult DeleteObject(MxDSAction* p_dsAction);

	// FUNCTION: BETA10 0x10158db0
	MxU8* GetMemoryBlock(MxU32 p_blockSize)
	{
		switch (p_blockSize) {
		case 0x40:
			return m_pool64.Get();

		case 0x80:
			return m_pool128.Get();

		default:
			assert("Invalid block size for memory pool" == NULL);
			break;
		}

		return NULL;
	}

	// FUNCTION: BETA10 0x10158570
	void ReleaseMemoryBlock(MxU8* p_block, MxU32 p_blockSize)
	{
		switch (p_blockSize) {
		case 0x40:
			m_pool64.Release(p_block);
			break;

		case 0x80:
			m_pool128.Release(p_block);
			break;

		default:
			assert("Invalid block size for memory pool" == NULL);
			break;
		}
	}

private:
	list<MxStreamController*> m_controllers; // 0x08
	MxMemoryPool64 m_pool64;                 // 0x14
	MxMemoryPool128 m_pool128;               // 0x20
};

// clang-format off
// TEMPLATE: LEGO1 0x100b9090
// TEMPLATE: BETA10 0x10146020
// list<MxStreamController *,allocator<MxStreamController *> >::~list<MxStreamController *,allocator<MxStreamController *> >
// clang-format on

// TEMPLATE: BETA10 0x10146090
// list<MxStreamController *,allocator<MxStreamController *> >::begin

// TEMPLATE: BETA10 0x10146120
// list<MxStreamController *,allocator<MxStreamController *> >::end

// TEMPLATE: BETA10 0x101461b0
// list<MxStreamController *,allocator<MxStreamController *> >::iterator::operator++

// SYNTHETIC: LEGO1 0x100b9120
// SYNTHETIC: BETA10 0x101466e0
// MxStreamer::`scalar deleting destructor'

// TEMPLATE: LEGO1 0x100b9140
// TEMPLATE: BETA10 0x10146720
// List<MxStreamController *>::~List<MxStreamController *>

// TEMPLATE: BETA10 0x10146ab0
// list<MxStreamController *,allocator<MxStreamController *> >::iterator::operator*

// SYNTHETIC: LEGO1 0x100b97b0
// SYNTHETIC: BETA10 0x10146f80
// MxStreamerNotification::`scalar deleting destructor'

// SYNTHETIC: LEGO1 0x100b9820
// SYNTHETIC: BETA10 0x10146fc0
// MxStreamerNotification::~MxStreamerNotification

// TEMPLATE: BETA10 0x10147020
// list<MxStreamController *,allocator<MxStreamController *> >::iterator::operator==

// TEMPLATE: BETA10 0x10147060
// list<MxStreamController *,allocator<MxStreamController *> >::push_back

// TEMPLATE: BETA10 0x10147200
// ??9@YAHABViterator@?$list@PAVMxStreamController@@V?$allocator@PAVMxStreamController@@@@@@0@Z

// clang-format off
// TEMPLATE: BETA10 0x10147230
// ?find@@YA?AViterator@?$list@PAVMxStreamController@@V?$allocator@PAVMxStreamController@@@@@@V12@0ABQAVMxStreamController@@@Z
// clang-format on

#endif // MXSTREAMER_H
