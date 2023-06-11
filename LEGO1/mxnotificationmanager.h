#ifdef MXNOTIFICATIONMANAGER_H
#define MXNOTIFICATIONMANAGER_H

// looks like tickle, only defined then used in its definition and never again
class MxNotificationManager : public MxCore
{
public:
	virtual ~MxNotificationManager();

	virtual long NotificationManager();
	virtual const char* GetClassName() const;
	virtual MxBool IsClass(const char* name) const;
};

#endif MXNOTIFICATIONMANAGER_H
