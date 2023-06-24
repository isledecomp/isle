#ifndef LEGOUTIL_H
#define LEGOUTIL_H

template <class T>
inline T Abs(T p_t)
{
    return p_t < 0 ? -p_t : p_t;
}
void ConvertColor(float r, float g, float b, float* out_r, float* out_g, float* out_b);
#endif // LEGOUTIL_H