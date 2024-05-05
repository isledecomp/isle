#ifndef MXOMNICREATEFLAGS_H
#define MXOMNICREATEFLAGS_H

#include "mxtypes.h"

// SIZE 0x02
class MxOmniCreateFlags {
public:
	MxOmniCreateFlags();

	// FUNCTION: BETA10 0x10092b50
	inline void CreateObjectFactory(MxBool p_enable) { this->m_flags1.m_bit0 = p_enable; }

	// FUNCTION: BETA10 0x10092b90
	inline void CreateTickleManager(MxBool p_enable) { this->m_flags1.m_bit2 = p_enable; }

	// FUNCTION: BETA10 0x10092bd0
	inline void CreateVideoManager(MxBool p_enable) { this->m_flags1.m_bit4 = p_enable; }

	// FUNCTION: BETA10 0x10092c10
	inline void CreateSoundManager(MxBool p_enable) { this->m_flags1.m_bit5 = p_enable; }

	// FUNCTION: BETA10 0x10130cd0
	inline const MxBool CreateObjectFactory() const { return this->m_flags1.m_bit0; }

	// FUNCTION: BETA10 0x10130cf0
	inline const MxBool CreateVariableTable() const { return this->m_flags1.m_bit1; }

	// FUNCTION: BETA10 0x10130d10
	inline const MxBool CreateTickleManager() const { return this->m_flags1.m_bit2; }

	// FUNCTION: BETA10 0x10130d30
	inline const MxBool CreateNotificationManager() const { return this->m_flags1.m_bit3; }

	// FUNCTION: BETA10 0x10130d50
	inline const MxBool CreateVideoManager() const { return this->m_flags1.m_bit4; }

	// FUNCTION: BETA10 0x10130d70
	inline const MxBool CreateSoundManager() const { return this->m_flags1.m_bit5; }

	// FUNCTION: BETA10 0x10130d90
	inline const MxBool CreateMusicManager() const { return this->m_flags1.m_bit6; }

	// FUNCTION: BETA10 0x10130db0
	inline const MxBool CreateEventManager() const { return this->m_flags1.m_bit7; }

	// FUNCTION: BETA10 0x10130dd0
	inline const MxBool CreateTimer() const { return this->m_flags2.m_bit1; }

	// FUNCTION: BETA10 0x10130e00
	inline const MxBool CreateStreamer() const { return this->m_flags2.m_bit2; }

private:
	FlagBitfield m_flags1;
	FlagBitfield m_flags2;
};

#endif // MXOMNICREATEFLAGS_H
