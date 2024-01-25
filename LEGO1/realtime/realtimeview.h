#ifndef REALTIMEVIEW_H
#define REALTIMEVIEW_H

class RealtimeView {
public:
	static float GetPartsThreshold();
	static float GetUserMaxLOD();
	static void SetPartsThreshold(float);
	static void UpdateMaxLOD();
	static void SetUserMaxLOD(float);
};

#endif // REALTIMEVIEW_H
