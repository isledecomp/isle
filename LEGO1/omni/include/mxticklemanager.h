#ifndef MXTICKLEMANAGER_H
#define MXTICKLEMANAGER_H

#include "mxcore.h"
#include "mxstl/stlcompat.h"
#include "mxtypes.h"

// SIZE 0x10
class MxTickleClient {
public:
	MxTickleClient(MxCore* p_client, MxTime p_interval);

	inline MxCore* GetClient() const { return m_client; }

	inline MxTime GetTickleInterval() const { return m_interval; }

	inline MxTime GetLastUpdateTime() const { return m_lastUpdateTime; }

	inline MxU16 GetFlags() const { return m_flags; }

	inline void SetTickleInterval(MxTime p_interval) { m_interval = p_interval; }

	inline void SetLastUpdateTime(MxTime p_lastUpdateTime) { m_lastUpdateTime = p_lastUpdateTime; }

	inline void SetFlags(MxU16 p_flags) { m_flags = p_flags; }

private:
	MxCore* m_client;        // 0x00
	MxTime m_interval;       // 0x04
	MxTime m_lastUpdateTime; // 0x08
	MxU16 m_flags;           // 0x0c
};

typedef list<MxTickleClient*> MxTickleClientPtrList;

// VTABLE: LEGO1 0x100d86d8
// SIZE 0x14
class MxTickleManager : public MxCore {
public:
	inline MxTickleManager() {}
	~MxTickleManager() override;

	MxResult Tickle() override;                                                // vtable+0x08
	virtual void RegisterClient(MxCore* p_client, MxTime p_interval);          // vtable+0x14
	virtual void UnregisterClient(MxCore* p_client);                           // vtable+0x18
	virtual void SetClientTickleInterval(MxCore* p_client, MxTime p_interval); // vtable+0x1c
	virtual MxTime GetClientTickleInterval(MxCore* p_client);                  // vtable+0x20

	// SYNTHETIC: LEGO1 0x1005a510
	// MxTickleManager::`scalar deleting destructor'

private:
	MxTickleClientPtrList m_clients; // 0x08
};

#define TICKLE_MANAGER_NOT_FOUND 0x80000000

// TEMPLATE: LEGO1 0x1005a4a0
// list<MxTickleClient *,allocator<MxTickleClient *> >::~list<MxTickleClient *,allocator<MxTickleClient *> >

// TEMPLATE: LEGO1 0x1005a530
// List<MxTickleClient *>::~List<MxTickleClient *>

#endif // MXTICKLEMANAGER_H
