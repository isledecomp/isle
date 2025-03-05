#ifndef MXTICKLEMANAGER_H
#define MXTICKLEMANAGER_H

#include "mxcore.h"
#include "mxstl/stlcompat.h"
#include "mxtypes.h"

// SIZE 0x10
class MxTickleClient {
public:
	MxTickleClient(MxCore* p_client, MxTime p_interval);

	MxCore* GetClient() const { return m_client; }

	MxTime GetTickleInterval() const { return m_interval; }

	MxTime GetLastUpdateTime() const { return m_lastUpdateTime; }

	MxU16 GetFlags() const { return m_flags; }

	void SetTickleInterval(MxTime p_interval) { m_interval = p_interval; }

	void SetLastUpdateTime(MxTime p_lastUpdateTime) { m_lastUpdateTime = p_lastUpdateTime; }

	void SetFlags(MxU16 p_flags) { m_flags = p_flags; }

private:
	MxCore* m_client;        // 0x00
	MxTime m_interval;       // 0x04
	MxTime m_lastUpdateTime; // 0x08
	MxU16 m_flags;           // 0x0c
};

typedef list<MxTickleClient*> MxTickleClientPtrList;

// VTABLE: LEGO1 0x100d86d8
// VTABLE: BETA10 0x101bc9d0
// SIZE 0x14
class MxTickleManager : public MxCore {
public:
	// FUNCTION: BETA10 0x100937c0
	MxTickleManager() {}

	~MxTickleManager() override;

	MxResult Tickle() override;                                                // vtable+0x08
	virtual void RegisterClient(MxCore* p_client, MxTime p_interval);          // vtable+0x14
	virtual void UnregisterClient(MxCore* p_client);                           // vtable+0x18
	virtual void SetClientTickleInterval(MxCore* p_client, MxTime p_interval); // vtable+0x1c
	virtual MxTime GetClientTickleInterval(MxCore* p_client);                  // vtable+0x20

	// SYNTHETIC: LEGO1 0x1005a510
	// SYNTHETIC: BETA10 0x100962f0
	// MxTickleManager::`scalar deleting destructor'

private:
	MxTickleClientPtrList m_clients; // 0x08
};

#define TICKLE_MANAGER_NOT_FOUND 0x80000000

// TEMPLATE: LEGO1 0x1005a4a0
// list<MxTickleClient *,allocator<MxTickleClient *> >::~list<MxTickleClient *,allocator<MxTickleClient *> >

// TEMPLATE: BETA10 0x10093870
// List<MxTickleClient *>::List<MxTickleClient *>

// TEMPLATE: LEGO1 0x1005a530
// TEMPLATE: BETA10 0x10096340
// List<MxTickleClient *>::~List<MxTickleClient *>

#endif // MXTICKLEMANAGER_H
