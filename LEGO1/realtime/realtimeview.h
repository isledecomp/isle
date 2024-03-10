#ifndef REALTIMEVIEW_H
#define REALTIMEVIEW_H

extern float g_userMaxLodPower;

class RealtimeView {
public:
	RealtimeView();
	~RealtimeView();

	static float GetPartsThreshold();
	static float GetUserMaxLOD();
	static void SetPartsThreshold(float);
	static void UpdateMaxLOD();
	static void SetUserMaxLOD(float);

	inline static float GetUserMaxLodPower() { return g_userMaxLodPower; }
};

#endif // REALTIMEVIEW_H
