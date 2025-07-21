#ifndef MXAUDIOMANAGER_H
#define MXAUDIOMANAGER_H

#include "decomp.h"
#include "mxpresentationmanager.h"

// VTABLE: LEGO1 0x100dc6e0
// VTABLE: BETA10 0x101c2348
// SIZE 0x30
class MxAudioManager : public MxPresentationManager {
public:
	MxAudioManager();
	~MxAudioManager() override;

	MxResult Create() override; // vtable+14
	void Destroy() override;    // vtable+18

	// FUNCTION: LEGO1 0x10029910
	// FUNCTION: BETA10 0x100d0630
	virtual MxS32 GetVolume() { return m_volume; } // vtable+28

	virtual void SetVolume(MxS32 p_volume); // vtable+2c

	// SYNTHETIC: LEGO1 0x100b8d70
	// SYNTHETIC: BETA10 0x10145110
	// MxAudioManager::`scalar deleting destructor'

private:
	void Destroy(MxBool p_fromDestructor);

	static MxS32 g_count;

protected:
	void Init();

	MxS32 m_volume; // 0x2c
};

#endif // MXAUDIOMANAGER_H
