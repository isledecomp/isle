#ifndef MXSTREAMER_H
#define MXSTREAMER_H

#include "decomp.h"
#include "mxcore.h"
#include "mxdsobject.h"
#include "mxnotificationparam.h"
#include "mxstreamcontroller.h"
#include "mxtypes.h"

#include <list>

// NOTE: This feels like some kind of templated class, maybe something from the
//       STL. But I haven't figured out what yet (it's definitely not a vector).
class MxStreamerSubClass1 {
public:
	inline MxStreamerSubClass1(undefined4 p_size)
	{
		m_buffer = NULL;
		m_size = p_size;
		undefined4* ptr = &m_unk0x08;
		for (int i = 0; i >= 0; i--) {
			ptr[i] = 0;
		}
	}

	// FUNCTION: LEGO1 0x100b9110
	~MxStreamerSubClass1() { delete[] m_buffer; }

	undefined4 GetSize() const { return m_size; }

	void SetBuffer(undefined* p_buf) { m_buffer = p_buf; }
	inline undefined* GetBuffer() const { return m_buffer; }
	inline undefined* GetUnk08Ref() const { return (undefined*) &m_unk0x08; }

private:
	undefined* m_buffer;
	undefined4 m_size;
	undefined4 m_unk0x08;
};

class MxStreamerSubClass2 : public MxStreamerSubClass1 {
public:
	inline MxStreamerSubClass2() : MxStreamerSubClass1(0x40) {}
};

class MxStreamerSubClass3 : public MxStreamerSubClass1 {
public:
	inline MxStreamerSubClass3() : MxStreamerSubClass1(0x80) {}
};

// VTABLE: LEGO1 0x100dc760
class MxStreamerNotification : public MxNotificationParam {
public:
	inline MxStreamerNotification(NotificationId p_type, MxCore* p_sender, MxStreamController* p_ctrlr)
		: MxNotificationParam(p_type, p_sender)
	{
		m_controller = p_ctrlr;
	}

	virtual MxNotificationParam* Clone() override;

	MxStreamController* GetController() { return m_controller; }

private:
	MxStreamController* m_controller;
};

// VTABLE: LEGO1 0x100dc710
// SIZE 0x2c
class MxStreamer : public MxCore {
public:
	enum OpenMode {
		e_DiskStream,
		e_RAMStream
	};

	MxStreamer();
	virtual ~MxStreamer() override; // vtable+0x0

	__declspec(dllexport) MxStreamController* Open(const char* p_name, MxU16 p_openMode);
	__declspec(dllexport) MxLong Close(const char* p_name);

	virtual MxLong Notify(MxParam& p_param) override; // vtable+0x4

	// FUNCTION: LEGO1 0x100b9000
	inline virtual const char* ClassName() const override // vtable+0x0c
	{
		// STRING: LEGO1 0x1010210c
		return "MxStreamer";
	}

	// FUNCTION: LEGO1 0x100b9010
	inline virtual MxBool IsA(const char* p_name) const override // vtable+0x10
	{
		return !strcmp(p_name, MxStreamer::ClassName()) || MxCore::IsA(p_name);
	}

	virtual MxResult Create(); // vtable+0x14

	MxBool FUN_100b9b30(MxDSObject& p_dsObject);
	MxStreamController* GetOpenStream(const char* p_name);
	MxResult AddStreamControllerToOpenList(MxStreamController* p_stream);
	MxResult FUN_100b99b0(MxDSAction* p_action);
	MxResult DeleteObject(MxDSAction* p_dsAction);

	inline const MxStreamerSubClass2& GetSubclass1() { return m_subclass1; }
	inline const MxStreamerSubClass3& GetSubclass2() { return m_subclass2; }

private:
	list<MxStreamController*> m_openStreams; // 0x8
	MxStreamerSubClass2 m_subclass1;         // 0x14
	MxStreamerSubClass3 m_subclass2;         // 0x20
};

// clang-format off
// TEMPLATE: LEGO1 0x100b9090
// list<MxStreamController *,allocator<MxStreamController *> >::~list<MxStreamController *,allocator<MxStreamController *> >
// clang-format on

// SYNTHETIC: LEGO1 0x100b9120
// MxStreamer::`scalar deleting destructor'

// TEMPLATE: LEGO1 0x100b9140
// List<MxStreamController *>::~List<MxStreamController *>

// SYNTHETIC: LEGO1 0x100b97b0
// MxStreamerNotification::`scalar deleting destructor'

// SYNTHETIC: LEGO1 0x100b9820
// MxStreamerNotification::~MxStreamerNotification

#endif // MXSTREAMER_H
