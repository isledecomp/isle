#ifndef MXOMNICREATEFLAGS_H
#define MXOMNICREATEFLAGS_H

#include "mxtypes.h"

class MxOmniCreateFlags {
public:
	enum LowFlags {
		c_createObjectFactory = 0x01,
		c_createVariableTable = 0x02,
		c_createTickleManager = 0x04,
		c_createNotificationManager = 0x08,
		c_createVideoManager = 0x10,
		c_createSoundManager = 0x20,
		c_createMusicManager = 0x40,
		c_createEventManager = 0x80
	};

	enum HighFlags {
		c_createTimer = 0x02,
		c_createStreamer = 0x04
	};

	__declspec(dllexport) MxOmniCreateFlags();

	inline const MxBool CreateObjectFactory() const { return this->m_flags1 & c_createObjectFactory; }
	inline const MxBool CreateVariableTable() const { return this->m_flags1 & c_createVariableTable; }
	inline const MxBool CreateTickleManager() const { return this->m_flags1 & c_createTickleManager; }
	inline const MxBool CreateNotificationManager() const { return this->m_flags1 & c_createNotificationManager; }
	inline const MxBool CreateVideoManager() const { return this->m_flags1 & c_createVideoManager; }
	inline const MxBool CreateSoundManager() const { return this->m_flags1 & c_createSoundManager; }
	inline const MxBool CreateMusicManager() const { return this->m_flags1 & c_createMusicManager; }
	inline const MxBool CreateEventManager() const { return this->m_flags1 & c_createEventManager; }

	inline const MxBool CreateTimer() const { return this->m_flags2 & c_createTimer; }
	inline const MxBool CreateStreamer() const { return this->m_flags2 & c_createStreamer; }

	inline void CreateObjectFactory(MxBool p_enable)
	{
		this->m_flags1 = (p_enable ? this->m_flags1 | c_createObjectFactory : this->m_flags1 & ~c_createObjectFactory);
	}
	inline void CreateVariableTable(MxBool p_enable)
	{
		this->m_flags1 = (p_enable ? this->m_flags1 | c_createVariableTable : this->m_flags1 & ~c_createVariableTable);
	}
	inline void CreateTickleManager(MxBool p_enable)
	{
		this->m_flags1 = (p_enable ? this->m_flags1 | c_createTickleManager : this->m_flags1 & ~c_createTickleManager);
	}
	inline void CreateNotificationManager(MxBool p_enable)
	{
		this->m_flags1 =
			(p_enable ? this->m_flags1 | c_createNotificationManager : this->m_flags1 & ~c_createNotificationManager);
	}
	inline void CreateVideoManager(MxBool p_enable)
	{
		this->m_flags1 = (p_enable ? this->m_flags1 | c_createVideoManager : this->m_flags1 & ~c_createVideoManager);
	}
	inline void CreateSoundManager(MxBool p_enable)
	{
		this->m_flags1 = (p_enable ? this->m_flags1 | c_createSoundManager : this->m_flags1 & ~c_createSoundManager);
	}
	inline void CreateMusicManager(MxBool p_enable)
	{
		this->m_flags1 = (p_enable ? this->m_flags1 | c_createMusicManager : this->m_flags1 & ~c_createMusicManager);
	}
	inline void CreateEventManager(MxBool p_enable)
	{
		this->m_flags1 = (p_enable ? this->m_flags1 | c_createEventManager : this->m_flags1 & ~c_createEventManager);
	}

	inline void CreateTimer(MxBool p_enable)
	{
		this->m_flags2 = (p_enable ? this->m_flags2 | c_createTimer : this->m_flags2 & ~c_createTimer);
	}
	inline void CreateStreamer(MxBool p_enable)
	{
		this->m_flags2 = (p_enable ? this->m_flags2 | c_createStreamer : this->m_flags2 & ~c_createStreamer);
	}

private:
	MxU8 m_flags1;
	MxU8 m_flags2;
};

#endif // MXOMNICREATEFLAGS_H
