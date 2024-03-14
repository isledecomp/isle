#ifndef MXSTREAMER_H
#define MXSTREAMER_H

#include "decomp.h"
#include "mxcore.h"
#include "mxdsobject.h"
#include "mxmemorypool.h"
#include "mxnotificationparam.h"
#include "mxstreamcontroller.h"
#include "mxtypes.h"

#include <assert.h>
#include <list>

typedef MxMemoryPool<64, 22> MxMemoryPool64;
typedef MxMemoryPool<128, 2> MxMemoryPool128;

// VTABLE: LEGO1 0x100dc760
class MxStreamerNotification : public MxNotificationParam {
public:
	inline MxStreamerNotification(NotificationId p_type, MxCore* p_sender, MxStreamController* p_ctrlr)
		: MxNotificationParam(p_type, p_sender)
	{
		m_controller = p_ctrlr;
	}

	MxNotificationParam* Clone() override;

	MxStreamController* GetController() { return m_controller; }

private:
	MxStreamController* m_controller;
};

// VTABLE: LEGO1 0x100dc710
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
	inline const char* ClassName() const override // vtable+0x0c
	{
		// STRING: LEGO1 0x1010210c
		return "MxStreamer";
	}

	// FUNCTION: LEGO1 0x100b9010
	inline MxBool IsA(const char* p_name) const override // vtable+0x10
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
	list<MxStreamController*> m_openStreams; // 0x08
	MxMemoryPool64 m_pool64;                 // 0x14
	MxMemoryPool128 m_pool128;               // 0x20
};

// clang-format off
// TEMPLATE: LEGO1 0x100b9090
// list<MxStreamController *,allocator<MxStreamController *> >::~list<MxStreamController *,allocator<MxStreamController *> >
// clang-format on

// TEMPLATE: LEGO1 0x100b9100
// MxMemoryPool<64,22>::~MxMemoryPool<64,22>

// TEMPLATE: LEGO1 0x100b9110
// MxMemoryPool<128,2>::~MxMemoryPool<128,2>

// SYNTHETIC: LEGO1 0x100b9120
// MxStreamer::`scalar deleting destructor'

// TEMPLATE: LEGO1 0x100b9140
// List<MxStreamController *>::~List<MxStreamController *>

// SYNTHETIC: LEGO1 0x100b97b0
// MxStreamerNotification::`scalar deleting destructor'

// SYNTHETIC: LEGO1 0x100b9820
// MxStreamerNotification::~MxStreamerNotification

#endif // MXSTREAMER_H
