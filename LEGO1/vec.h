/*
 * vec.h --  Vector macros for 2,3, and 4 dimensions,
 *           for any  combination of C scalar types.
 *
 * Author:		Don Hatch (hatch@sgi.com)
 * Last modified:	Fri Sep 30 03:23:02 PDT 1994
 *
 * General description:
 *
 *	The macro name describes its arguments; e.g.
 *	    	MXS3 is "matrix times scalar in 3 dimensions";
 *	    	VMV2 is "vector minus vector in 2 dimensions".
 *
 *	If the result of an operation is a scalar, then the macro "returns"
 *	the value; e.g.
 *	    	result = DOT3(v,w);
 *	    	result = DET4(m);
 *
 *	If the result of an operation is a vector or matrix, then
 *	the first argument is the destination; e.g.
 *	    	SET2(tovec, fromvec);
 *	    	MXM3(result, m1, m2);
 *
 *  WARNING: For the operations that are not done "componentwise"
 *	    (e.g. vector cross products and matrix multiplies)
 *	    the destination should not be either of the arguments,
 *	    for obvious reasons.  For example, the following is wrong:
 *		VXM2(v,v,m);
 *          For such "unsafe" macros, there are safe versions provided,
 *          but you have to specify a type for the temporary
 *	    result vector or matrix.  For example, the safe versions
 *	    of VXM2 are:
 *              VXM2d(v,v,m)    if v's scalar type is double or float
 *              VXM2i(v,v,m)    if v's scalar type is int or char
 *              VXM2l(v,v,m)    if v's scalar type is long
 *              VXM2r(v,v,m)    if v's scalar type is real
 *              VXM2safe(type,v,v,m) for other scalar types.
 *	    These "safe" macros do not evaluate to C expressions
 *	    (so, for example, they can't be used inside the parentheses of
 *	    a for(...)).
 *
 *  Specific descriptions:
 *
 *	The "?"'s in the following can be 2, 3, or 4.
 *
 *	SET?(to,from)			to = from
 *	SETMAT?(to,from)		to = from
 *	ROUNDVEC?(to,from)		to = from with entries rounded
 *							to nearest integer
 *	ROUNDMAT?(to,from)		to = from with entries rounded
 *							to nearest integer
 *	FILLVEC?(v,s)			set each entry of vector v to be s
 *	FILLMAT?(m,s)			set each entry of matrix m to be s
 *	ZEROVEC?(v)			v = 0
 *	ISZEROVEC?(v)			v == 0
 *	EQVEC?(v,w)			v == w
 *	EQMAT?(m1,m2)			m1 == m2
 *	ZEROMAT?(m)			m = 0
 *	IDENTMAT?(m)			m = 1
 *	TRANSPOSE?(to,from)		(matrix to) = (transpose of matrix from)
 *	ADJOINT?(to,from)		(matrix to) = (adjoint of matrix from)
 *					 i.e. its determinant times its inverse
 *
 *	V{P,M}V?(to,v,w)		to = v {+,-} w
 *	M{P,M}M?(to,m1,m2)		to = m1 {+,-} m2
 *	SX{V,M}?(to,s,from)		to = s * from
 *	M{V,M}?(to,from)		to = -from
 *	{V,M}{X,D}S?(to,from,s)		to = from {*,/} s
 *	MXM?(to,m1,m2)			to = m1 * m2
 *	VXM?(to,v,m)			(row vec to) = (row vec v) * m
 *	MXV?(to,m,v)			(column vec to) = m * (column vec v)
 *	LERP?(to,v0,v1,t)		to = v0 + t*(v1-v0)
 *
 *	DET?(m)				determinant of m
 *	TRACE?(m)			trace (sum of diagonal entries) of m
 *	DOT?(v,w)			dot (scalar) product of v and w
 *	NORMSQRD?(v)			square of |v|
 *	DISTSQRD?(v,w)			square of |v-w|
 *
 *	XV2(to,v)			to = v rotated by 90 degrees
 *	VXV3(to,v1,v2)			to = cross (vector) product of v1 and v2
 *	VXVXV4(to,v1,v2,v3)		to = 4-dimensional vector cross product
 *					 of v1,v2,v3 (a vector orthogonal to
 *					 v1,v2,v3 whose length equals the
 *					 volume of the spanned parallelotope)
 *	VXV2(v0,v1)			determinant of matrix with rows v0,v1
 *	VXVXV3(v0,v1,v2)		determinant of matrix with rows v0,v1,v2
 *	VXVXVXV4(v0,v1,v2,v3)		determinant of matrix with rows v0,..,v3
 *
 *   The following macros mix objects from different dimensions.
 *   For example, V3XM4 would be used to apply a composite
 *   4x4 rotation-and-translation matrix to a 3d vector.
 *
 *	SET3from2(to,from,pad)		(3d vec to) = (2d vec from) with pad
 *	SET4from3(to,from,pad)		(4d vec to) = (3d vec from) with pad
 *	SETMAT3from2(to,from,pad0,pad1) (3x3 mat to) = (2x2 mat from)
 *					 padded with pad0 on the sides
 *					 and pad1 in the corner
 *	SETMAT4from3(to,from,pad0,pad1) (4x4 mat to) = (3x3 mat from)
 *					 padded with pad0 on the sides
 *					 and pad1 in the corner
 *	V2XM3(to2,v2,m3)       (2d row vec to2) = (2d row vec v2) * (3x3 mat m3)
 *	V3XM4(to3,v3,m4)       (3d row vec to3) = (3d row vec v2) * (4x4 mat m4)
 *	M3XV2(to2,m3,v2)       (2d col vec to2) = (3x3 mat m3) * (2d col vec v2)
 *	M4XV3(to3,m4,v3)       (3d col vec to3) = (4x4 mat m4) * (3d col vec v3)
 *	M2XM3(to3,m2,m3)       (3x3 mat to3) = (2x2 mat m2) * (3x3 mat m3)
 *	M3XM4(to4,m3,m4)       (4x4 mat to4) = (3x3 mat m3) * (4x4 mat m4)
 *	M3XM2(to3,m3,m2)       (3x3 mat to3) = (3x3 mat m3) * (2x2 mat m2)
 *	M4XM3(to4,m4,m3)       (4x4 mat to4) = (4x4 mat m4) * (3x3 mat m3)
 *
 *
 *   This file is machine-generated and can be regenerated
 *   for any number of dimensions.
 *   The program that generated it is available upon request.
 */

#ifndef VEC_H
#define VEC_H 4
#include <math.h>	/* for definition of floor() */
#define SET2(to,from)	\
		((to)[0] = (from)[0], \
		 (to)[1] = (from)[1])
#define SETMAT2(to,from)	\
		(SET2((to)[0], (from)[0]), \
		 SET2((to)[1], (from)[1]))
#define ROUNDVEC2(to,from)	\
		((to)[0] = floor((from)[0]+.5), \
		 (to)[1] = floor((from)[1]+.5))
#define ROUNDMAT2(to,from)	\
		(ROUNDVEC2((to)[0], (from)[0]), \
		 ROUNDVEC2((to)[1], (from)[1]))
#define FILLVEC2(v,s)	\
		((v)[0] = (s), \
		 (v)[1] = (s))
#define FILLMAT2(m,s)	\
		(FILLVEC2((m)[0], s), \
		 FILLVEC2((m)[1], s))
#define ZEROVEC2(v)	\
		((v)[0] = 0, \
		 (v)[1] = 0)
#define ISZEROVEC2(v)	\
		((v)[0] == 0 && \
		 (v)[1] == 0)
#define EQVEC2(v,w)	\
		((v)[0] == (w)[0] && \
		 (v)[1] == (w)[1])
#define EQMAT2(m1,m2)	\
		(EQVEC2((m1)[0], (m2)[0]) && \
		 EQVEC2((m1)[1], (m2)[1]))
#define ZEROMAT2(m)	\
		(ZEROVEC2((m)[0]), \
		 ZEROVEC2((m)[1]))
#define IDENTMAT2(m)	\
		(ZEROVEC2((m)[0]), (m)[0][0]=1, \
		 ZEROVEC2((m)[1]), (m)[1][1]=1)
#define TRANSPOSE2(to,from)	\
		(_SETcol2((to)[0], from, 0), \
		 _SETcol2((to)[1], from, 1))
#define VPV2(to,v,w)	\
		((to)[0] = (v)[0] + (w)[0], \
		 (to)[1] = (v)[1] + (w)[1])
#define VMV2(to,v,w)	\
		((to)[0] = (v)[0] - (w)[0], \
		 (to)[1] = (v)[1] - (w)[1])
#define MPM2(to,m1,m2)	\
		(VPV2((to)[0], (m1)[0], (m2)[0]), \
		 VPV2((to)[1], (m1)[1], (m2)[1]))
#define MMM2(to,m1,m2)	\
		(VMV2((to)[0], (m1)[0], (m2)[0]), \
		 VMV2((to)[1], (m1)[1], (m2)[1]))
#define SXV2(to,s,from)	\
		((to)[0] = (s) * (from)[0], \
		 (to)[1] = (s) * (from)[1])
#define SXM2(to,s,from)	\
		(SXV2((to)[0], s, (from)[0]), \
		 SXV2((to)[1], s, (from)[1]))
#define MV2(to,from)	\
		((to)[0] = -(from)[0], \
		 (to)[1] = -(from)[1])
#define MM2(to,from)	\
		(MV2((to)[0], (from)[0]), \
		 MV2((to)[1], (from)[1]))
#define VXS2(to,from,s)	\
		((to)[0] = (from)[0] * (s), \
		 (to)[1] = (from)[1] * (s))
#define VDS2(to,from,s)	\
		((to)[0] = (from)[0] / (s), \
		 (to)[1] = (from)[1] / (s))
#define MXS2(to,from,s)	\
		(VXS2((to)[0], (from)[0], s), \
		 VXS2((to)[1], (from)[1], s))
#define MDS2(to,from,s)	\
		(VDS2((to)[0], (from)[0], s), \
		 VDS2((to)[1], (from)[1], s))
#define MXM2(to,m1,m2)	\
		(VXM2((to)[0], (m1)[0], m2), \
		 VXM2((to)[1], (m1)[1], m2))
#define VXM2(to,v,m)	\
		((to)[0] = _DOTcol2(v, m, 0), \
		 (to)[1] = _DOTcol2(v, m, 1))
#define MXV2(to,m,v)	\
		((to)[0] = DOT2((m)[0], v), \
		 (to)[1] = DOT2((m)[1], v))
#define LERP2(to,v0,v1,t)	\
		((to)[0]=(v0)[0]+(t)*((v1)[0]-(v0)[0]), \
		 (to)[1]=(v0)[1]+(t)*((v1)[1]-(v0)[1]))
#define TRACE2(m)	\
		((m)[0][0] + \
		 (m)[1][1])
#define DOT2(v,w)	\
		((v)[0] * (w)[0] + \
		 (v)[1] * (w)[1])
#define NORMSQRD2(v)	\
		((v)[0] * (v)[0] + \
		 (v)[1] * (v)[1])
#define DISTSQRD2(v,w)	\
		(((v)[0]-(w)[0])*((v)[0]-(w)[0]) + \
		 ((v)[1]-(w)[1])*((v)[1]-(w)[1]))
#define _DOTcol2(v,m,j)	\
		((v)[0] * (m)[0][j] + \
		 (v)[1] * (m)[1][j])
#define _SETcol2(v,m,j)	\
		((v)[0] = (m)[0][j], \
		 (v)[1] = (m)[1][j])
#define _MXVcol2(to,m,M,j)	\
		((to)[0][j] = _DOTcol2((m)[0],M,j), \
		 (to)[1][j] = _DOTcol2((m)[1],M,j))
#define _DET2(v0,v1,i0,i1)	\
		((v0)[i0]* _DET1(v1,i1) + \
		 (v0)[i1]*-_DET1(v1,i0))
#define XV2(to,v1)	\
		((to)[0] = -_DET1(v1, 1), \
		 (to)[1] =  _DET1(v1, 0))
#define V2XM3(to2,v2,m3)	\
		((to2)[0] = _DOTcol2(v2,m3,0) + (m3)[2][0], \
		 (to2)[1] = _DOTcol2(v2,m3,1) + (m3)[2][1])
#define M3XV2(to2,m3,v2)	\
		((to2)[0] = DOT2((m3)[0],v2) + (m3)[0][2], \
		 (to2)[1] = DOT2((m3)[1],v2) + (m3)[1][2])
#define _DET1(v0,i0)	\
		((v0)[i0])
#define VXV2(v0,v1)	\
		(_DET2(v0,v1,0,1))
#define DET2(m)	\
		(VXV2((m)[0],(m)[1]))
#define ADJOINT2(to,m)	\
		( _ADJOINTcol2(to,0,m,1), \
		 __ADJOINTcol2(to,1,m,0))
#define _ADJOINTcol2(to,col,m,i1)	\
		((to)[0][col] =  _DET1(m[i1], 1), \
		 (to)[1][col] = -_DET1(m[i1], 0))
#define __ADJOINTcol2(to,col,m,i1)	\
		((to)[0][col] = -_DET1(m[i1], 1), \
		 (to)[1][col] =  _DET1(m[i1], 0))
#define SET3(to,from)	\
		((to)[0] = (from)[0], \
		 (to)[1] = (from)[1], \
		 (to)[2] = (from)[2])
#define SETMAT3(to,from)	\
		(SET3((to)[0], (from)[0]), \
		 SET3((to)[1], (from)[1]), \
		 SET3((to)[2], (from)[2]))
#define ROUNDVEC3(to,from)	\
		((to)[0] = floor((from)[0]+.5), \
		 (to)[1] = floor((from)[1]+.5), \
		 (to)[2] = floor((from)[2]+.5))
#define ROUNDMAT3(to,from)	\
		(ROUNDVEC3((to)[0], (from)[0]), \
		 ROUNDVEC3((to)[1], (from)[1]), \
		 ROUNDVEC3((to)[2], (from)[2]))
#define FILLVEC3(v,s)	\
		((v)[0] = (s), \
		 (v)[1] = (s), \
		 (v)[2] = (s))
#define FILLMAT3(m,s)	\
		(FILLVEC3((m)[0], s), \
		 FILLVEC3((m)[1], s), \
		 FILLVEC3((m)[2], s))
#define ZEROVEC3(v)	\
		((v)[0] = 0, \
		 (v)[1] = 0, \
		 (v)[2] = 0)
#define ISZEROVEC3(v)	\
		((v)[0] == 0 && \
		 (v)[1] == 0 && \
		 (v)[2] == 0)
#define EQVEC3(v,w)	\
		((v)[0] == (w)[0] && \
		 (v)[1] == (w)[1] && \
		 (v)[2] == (w)[2])
#define EQMAT3(m1,m2)	\
		(EQVEC3((m1)[0], (m2)[0]) && \
		 EQVEC3((m1)[1], (m2)[1]) && \
		 EQVEC3((m1)[2], (m2)[2]))
#define ZEROMAT3(m)	\
		(ZEROVEC3((m)[0]), \
		 ZEROVEC3((m)[1]), \
		 ZEROVEC3((m)[2]))
#define IDENTMAT3(m)	\
		(ZEROVEC3((m)[0]), (m)[0][0]=1, \
		 ZEROVEC3((m)[1]), (m)[1][1]=1, \
		 ZEROVEC3((m)[2]), (m)[2][2]=1)
#define TRANSPOSE3(to,from)	\
		(_SETcol3((to)[0], from, 0), \
		 _SETcol3((to)[1], from, 1), \
		 _SETcol3((to)[2], from, 2))
#define VPV3(to,v,w)	\
		((to)[0] = (v)[0] + (w)[0], \
		 (to)[1] = (v)[1] + (w)[1], \
		 (to)[2] = (v)[2] + (w)[2])
#define VMV3(to,v,w)	\
		((to)[0] = (v)[0] - (w)[0], \
		 (to)[1] = (v)[1] - (w)[1], \
		 (to)[2] = (v)[2] - (w)[2])
#define MPM3(to,m1,m2)	\
		(VPV3((to)[0], (m1)[0], (m2)[0]), \
		 VPV3((to)[1], (m1)[1], (m2)[1]), \
		 VPV3((to)[2], (m1)[2], (m2)[2]))
#define MMM3(to,m1,m2)	\
		(VMV3((to)[0], (m1)[0], (m2)[0]), \
		 VMV3((to)[1], (m1)[1], (m2)[1]), \
		 VMV3((to)[2], (m1)[2], (m2)[2]))
#define SXV3(to,s,from)	\
		((to)[0] = (s) * (from)[0], \
		 (to)[1] = (s) * (from)[1], \
		 (to)[2] = (s) * (from)[2])
#define SXM3(to,s,from)	\
		(SXV3((to)[0], s, (from)[0]), \
		 SXV3((to)[1], s, (from)[1]), \
		 SXV3((to)[2], s, (from)[2]))
#define MV3(to,from)	\
		((to)[0] = -(from)[0], \
		 (to)[1] = -(from)[1], \
		 (to)[2] = -(from)[2])
#define MM3(to,from)	\
		(MV3((to)[0], (from)[0]), \
		 MV3((to)[1], (from)[1]), \
		 MV3((to)[2], (from)[2]))
#define VXS3(to,from,s)	\
		((to)[0] = (from)[0] * (s), \
		 (to)[1] = (from)[1] * (s), \
		 (to)[2] = (from)[2] * (s))
#define VDS3(to,from,s)	\
		((to)[0] = (from)[0] / (s), \
		 (to)[1] = (from)[1] / (s), \
		 (to)[2] = (from)[2] / (s))
#define MXS3(to,from,s)	\
		(VXS3((to)[0], (from)[0], s), \
		 VXS3((to)[1], (from)[1], s), \
		 VXS3((to)[2], (from)[2], s))
#define MDS3(to,from,s)	\
		(VDS3((to)[0], (from)[0], s), \
		 VDS3((to)[1], (from)[1], s), \
		 VDS3((to)[2], (from)[2], s))
#define MXM3(to,m1,m2)	\
		(VXM3((to)[0], (m1)[0], m2), \
		 VXM3((to)[1], (m1)[1], m2), \
		 VXM3((to)[2], (m1)[2], m2))
#define VXM3(to,v,m)	\
		((to)[0] = _DOTcol3(v, m, 0), \
		 (to)[1] = _DOTcol3(v, m, 1), \
		 (to)[2] = _DOTcol3(v, m, 2))
#define MXV3(to,m,v)	\
		((to)[0] = DOT3((m)[0], v), \
		 (to)[1] = DOT3((m)[1], v), \
		 (to)[2] = DOT3((m)[2], v))
#define LERP3(to,v0,v1,t)	\
		((to)[0]=(v0)[0]+(t)*((v1)[0]-(v0)[0]), \
		 (to)[1]=(v0)[1]+(t)*((v1)[1]-(v0)[1]), \
		 (to)[2]=(v0)[2]+(t)*((v1)[2]-(v0)[2]))
#define TRACE3(m)	\
		((m)[0][0] + \
		 (m)[1][1] + \
		 (m)[2][2])
#define DOT3(v,w)	\
		((v)[0] * (w)[0] + \
		 (v)[1] * (w)[1] + \
		 (v)[2] * (w)[2])
#define NORMSQRD3(v)	\
		((v)[0] * (v)[0] + \
		 (v)[1] * (v)[1] + \
		 (v)[2] * (v)[2])
#define DISTSQRD3(v,w)	\
		(((v)[0]-(w)[0])*((v)[0]-(w)[0]) + \
		 ((v)[1]-(w)[1])*((v)[1]-(w)[1]) + \
		 ((v)[2]-(w)[2])*((v)[2]-(w)[2]))
#define _DOTcol3(v,m,j)	\
		((v)[0] * (m)[0][j] + \
		 (v)[1] * (m)[1][j] + \
		 (v)[2] * (m)[2][j])
#define _SETcol3(v,m,j)	\
		((v)[0] = (m)[0][j], \
		 (v)[1] = (m)[1][j], \
		 (v)[2] = (m)[2][j])
#define _MXVcol3(to,m,M,j)	\
		((to)[0][j] = _DOTcol3((m)[0],M,j), \
		 (to)[1][j] = _DOTcol3((m)[1],M,j), \
		 (to)[2][j] = _DOTcol3((m)[2],M,j))
#define _DET3(v0,v1,v2,i0,i1,i2)	\
		((v0)[i0]* _DET2(v1,v2,i1,i2) + \
		 (v0)[i1]*-_DET2(v1,v2,i0,i2) + \
		 (v0)[i2]* _DET2(v1,v2,i0,i1))
#define VXV3(to,v1,v2)	\
		((to)[0] =  _DET2(v1,v2, 1,2), \
		 (to)[1] = -_DET2(v1,v2, 0,2), \
		 (to)[2] =  _DET2(v1,v2, 0,1))
#define SET3from2(to,from,pad)	\
		((to)[0] = (from)[0], \
		 (to)[1] = (from)[1], \
		 (to)[2] = (pad))
#define SETMAT3from2(to,from,pad0,pad1)	\
		(SET3from2((to)[0], (from)[0], pad0), \
		 SET3from2((to)[1], (from)[1], pad0), \
		 FILLVEC2((to)[2], (pad0)), (to)[2][2] = (pad1))
#define M2XM3(to3,m2,m3)	\
		(_MXVcol2(to3,m2,m3,0), (to3)[2][0]=(m3)[2][0], \
		 _MXVcol2(to3,m2,m3,1), (to3)[2][1]=(m3)[2][1], \
		 _MXVcol2(to3,m2,m3,2), (to3)[2][2]=(m3)[2][2])
#define M3XM2(to3,m3,m2)	\
		(VXM2((to3)[0],(m3)[0],m2), (to3)[0][2]=(m3)[0][2], \
		 VXM2((to3)[1],(m3)[1],m2), (to3)[1][2]=(m3)[1][2], \
		 VXM2((to3)[2],(m3)[2],m2), (to3)[2][2]=(m3)[2][2])
#define V3XM4(to3,v3,m4)	\
		((to3)[0] = _DOTcol3(v3,m4,0) + (m4)[3][0], \
		 (to3)[1] = _DOTcol3(v3,m4,1) + (m4)[3][1], \
		 (to3)[2] = _DOTcol3(v3,m4,2) + (m4)[3][2])
#define M4XV3(to3,m4,v3)	\
		((to3)[0] = DOT3((m4)[0],v3) + (m4)[0][3], \
		 (to3)[1] = DOT3((m4)[1],v3) + (m4)[1][3], \
		 (to3)[2] = DOT3((m4)[2],v3) + (m4)[2][3])
#define VXVXV3(v0,v1,v2)	\
		(_DET3(v0,v1,v2,0,1,2))
#define DET3(m)	\
		(VXVXV3((m)[0],(m)[1],(m)[2]))
#define ADJOINT3(to,m)	\
		( _ADJOINTcol3(to,0,m,1,2), \
		 __ADJOINTcol3(to,1,m,0,2), \
		  _ADJOINTcol3(to,2,m,0,1))
#define _ADJOINTcol3(to,col,m,i1,i2)	\
		((to)[0][col] =  _DET2(m[i1],m[i2], 1,2), \
		 (to)[1][col] = -_DET2(m[i1],m[i2], 0,2), \
		 (to)[2][col] =  _DET2(m[i1],m[i2], 0,1))
#define __ADJOINTcol3(to,col,m,i1,i2)	\
		((to)[0][col] = -_DET2(m[i1],m[i2], 1,2), \
		 (to)[1][col] =  _DET2(m[i1],m[i2], 0,2), \
		 (to)[2][col] = -_DET2(m[i1],m[i2], 0,1))
#define SET4(to,from)	\
		((to)[0] = (from)[0], \
		 (to)[1] = (from)[1], \
		 (to)[2] = (from)[2], \
		 (to)[3] = (from)[3])
#define SETMAT4(to,from)	\
		(SET4((to)[0], (from)[0]), \
		 SET4((to)[1], (from)[1]), \
		 SET4((to)[2], (from)[2]), \
		 SET4((to)[3], (from)[3]))
#define ROUNDVEC4(to,from)	\
		((to)[0] = floor((from)[0]+.5), \
		 (to)[1] = floor((from)[1]+.5), \
		 (to)[2] = floor((from)[2]+.5), \
		 (to)[3] = floor((from)[3]+.5))
#define ROUNDMAT4(to,from)	\
		(ROUNDVEC4((to)[0], (from)[0]), \
		 ROUNDVEC4((to)[1], (from)[1]), \
		 ROUNDVEC4((to)[2], (from)[2]), \
		 ROUNDVEC4((to)[3], (from)[3]))
#define FILLVEC4(v,s)	\
		((v)[0] = (s), \
		 (v)[1] = (s), \
		 (v)[2] = (s), \
		 (v)[3] = (s))
#define FILLMAT4(m,s)	\
		(FILLVEC4((m)[0], s), \
		 FILLVEC4((m)[1], s), \
		 FILLVEC4((m)[2], s), \
		 FILLVEC4((m)[3], s))
#define ZEROVEC4(v)	\
		((v)[0] = 0, \
		 (v)[1] = 0, \
		 (v)[2] = 0, \
		 (v)[3] = 0)
#define ISZEROVEC4(v)	\
		((v)[0] == 0 && \
		 (v)[1] == 0 && \
		 (v)[2] == 0 && \
		 (v)[3] == 0)
#define EQVEC4(v,w)	\
		((v)[0] == (w)[0] && \
		 (v)[1] == (w)[1] && \
		 (v)[2] == (w)[2] && \
		 (v)[3] == (w)[3])
#define EQMAT4(m1,m2)	\
		(EQVEC4((m1)[0], (m2)[0]) && \
		 EQVEC4((m1)[1], (m2)[1]) && \
		 EQVEC4((m1)[2], (m2)[2]) && \
		 EQVEC4((m1)[3], (m2)[3]))
#define ZEROMAT4(m)	\
		(ZEROVEC4((m)[0]), \
		 ZEROVEC4((m)[1]), \
		 ZEROVEC4((m)[2]), \
		 ZEROVEC4((m)[3]))
#define IDENTMAT4(m)	\
		(ZEROVEC4((m)[0]), (m)[0][0]=1, \
		 ZEROVEC4((m)[1]), (m)[1][1]=1, \
		 ZEROVEC4((m)[2]), (m)[2][2]=1, \
		 ZEROVEC4((m)[3]), (m)[3][3]=1)
#define TRANSPOSE4(to,from)	\
		(_SETcol4((to)[0], from, 0), \
		 _SETcol4((to)[1], from, 1), \
		 _SETcol4((to)[2], from, 2), \
		 _SETcol4((to)[3], from, 3))
#define VPV4(to,v,w)	\
		((to)[0] = (v)[0] + (w)[0], \
		 (to)[1] = (v)[1] + (w)[1], \
		 (to)[2] = (v)[2] + (w)[2], \
		 (to)[3] = (v)[3] + (w)[3])
#define VMV4(to,v,w)	\
		((to)[0] = (v)[0] - (w)[0], \
		 (to)[1] = (v)[1] - (w)[1], \
		 (to)[2] = (v)[2] - (w)[2], \
		 (to)[3] = (v)[3] - (w)[3])
#define MPM4(to,m1,m2)	\
		(VPV4((to)[0], (m1)[0], (m2)[0]), \
		 VPV4((to)[1], (m1)[1], (m2)[1]), \
		 VPV4((to)[2], (m1)[2], (m2)[2]), \
		 VPV4((to)[3], (m1)[3], (m2)[3]))
#define MMM4(to,m1,m2)	\
		(VMV4((to)[0], (m1)[0], (m2)[0]), \
		 VMV4((to)[1], (m1)[1], (m2)[1]), \
		 VMV4((to)[2], (m1)[2], (m2)[2]), \
		 VMV4((to)[3], (m1)[3], (m2)[3]))
#define SXV4(to,s,from)	\
		((to)[0] = (s) * (from)[0], \
		 (to)[1] = (s) * (from)[1], \
		 (to)[2] = (s) * (from)[2], \
		 (to)[3] = (s) * (from)[3])
#define SXM4(to,s,from)	\
		(SXV4((to)[0], s, (from)[0]), \
		 SXV4((to)[1], s, (from)[1]), \
		 SXV4((to)[2], s, (from)[2]), \
		 SXV4((to)[3], s, (from)[3]))
#define MV4(to,from)	\
		((to)[0] = -(from)[0], \
		 (to)[1] = -(from)[1], \
		 (to)[2] = -(from)[2], \
		 (to)[3] = -(from)[3])
#define MM4(to,from)	\
		(MV4((to)[0], (from)[0]), \
		 MV4((to)[1], (from)[1]), \
		 MV4((to)[2], (from)[2]), \
		 MV4((to)[3], (from)[3]))
#define VXS4(to,from,s)	\
		((to)[0] = (from)[0] * (s), \
		 (to)[1] = (from)[1] * (s), \
		 (to)[2] = (from)[2] * (s), \
		 (to)[3] = (from)[3] * (s))
#define VDS4(to,from,s)	\
		((to)[0] = (from)[0] / (s), \
		 (to)[1] = (from)[1] / (s), \
		 (to)[2] = (from)[2] / (s), \
		 (to)[3] = (from)[3] / (s))
#define MXS4(to,from,s)	\
		(VXS4((to)[0], (from)[0], s), \
		 VXS4((to)[1], (from)[1], s), \
		 VXS4((to)[2], (from)[2], s), \
		 VXS4((to)[3], (from)[3], s))
#define MDS4(to,from,s)	\
		(VDS4((to)[0], (from)[0], s), \
		 VDS4((to)[1], (from)[1], s), \
		 VDS4((to)[2], (from)[2], s), \
		 VDS4((to)[3], (from)[3], s))
#define MXM4(to,m1,m2)	\
		(VXM4((to)[0], (m1)[0], m2), \
		 VXM4((to)[1], (m1)[1], m2), \
		 VXM4((to)[2], (m1)[2], m2), \
		 VXM4((to)[3], (m1)[3], m2))
#define VXM4(to,v,m)	\
		((to)[0] = _DOTcol4(v, m, 0), \
		 (to)[1] = _DOTcol4(v, m, 1), \
		 (to)[2] = _DOTcol4(v, m, 2), \
		 (to)[3] = _DOTcol4(v, m, 3))
#define MXV4(to,m,v)	\
		((to)[0] = DOT4((m)[0], v), \
		 (to)[1] = DOT4((m)[1], v), \
		 (to)[2] = DOT4((m)[2], v), \
		 (to)[3] = DOT4((m)[3], v))
#define LERP4(to,v0,v1,t)	\
		((to)[0]=(v0)[0]+(t)*((v1)[0]-(v0)[0]), \
		 (to)[1]=(v0)[1]+(t)*((v1)[1]-(v0)[1]), \
		 (to)[2]=(v0)[2]+(t)*((v1)[2]-(v0)[2]), \
		 (to)[3]=(v0)[3]+(t)*((v1)[3]-(v0)[3]))
#define TRACE4(m)	\
		((m)[0][0] + \
		 (m)[1][1] + \
		 (m)[2][2] + \
		 (m)[3][3])
#define DOT4(v,w)	\
		((v)[0] * (w)[0] + \
		 (v)[1] * (w)[1] + \
		 (v)[2] * (w)[2] + \
		 (v)[3] * (w)[3])
#define NORMSQRD4(v)	\
		((v)[0] * (v)[0] + \
		 (v)[1] * (v)[1] + \
		 (v)[2] * (v)[2] + \
		 (v)[3] * (v)[3])
#define DISTSQRD4(v,w)	\
		(((v)[0]-(w)[0])*((v)[0]-(w)[0]) + \
		 ((v)[1]-(w)[1])*((v)[1]-(w)[1]) + \
		 ((v)[2]-(w)[2])*((v)[2]-(w)[2]) + \
		 ((v)[3]-(w)[3])*((v)[3]-(w)[3]))
#define _DOTcol4(v,m,j)	\
		((v)[0] * (m)[0][j] + \
		 (v)[1] * (m)[1][j] + \
		 (v)[2] * (m)[2][j] + \
		 (v)[3] * (m)[3][j])
#define _SETcol4(v,m,j)	\
		((v)[0] = (m)[0][j], \
		 (v)[1] = (m)[1][j], \
		 (v)[2] = (m)[2][j], \
		 (v)[3] = (m)[3][j])
#define _MXVcol4(to,m,M,j)	\
		((to)[0][j] = _DOTcol4((m)[0],M,j), \
		 (to)[1][j] = _DOTcol4((m)[1],M,j), \
		 (to)[2][j] = _DOTcol4((m)[2],M,j), \
		 (to)[3][j] = _DOTcol4((m)[3],M,j))
#define _DET4(v0,v1,v2,v3,i0,i1,i2,i3)	\
		((v0)[i0]* _DET3(v1,v2,v3,i1,i2,i3) + \
		 (v0)[i1]*-_DET3(v1,v2,v3,i0,i2,i3) + \
		 (v0)[i2]* _DET3(v1,v2,v3,i0,i1,i3) + \
		 (v0)[i3]*-_DET3(v1,v2,v3,i0,i1,i2))
#define VXVXV4(to,v1,v2,v3)	\
		((to)[0] = -_DET3(v1,v2,v3, 1,2,3), \
		 (to)[1] =  _DET3(v1,v2,v3, 0,2,3), \
		 (to)[2] = -_DET3(v1,v2,v3, 0,1,3), \
		 (to)[3] =  _DET3(v1,v2,v3, 0,1,2))
#define SET4from3(to,from,pad)	\
		((to)[0] = (from)[0], \
		 (to)[1] = (from)[1], \
		 (to)[2] = (from)[2], \
		 (to)[3] = (pad))
#define SETMAT4from3(to,from,pad0,pad1)	\
		(SET4from3((to)[0], (from)[0], pad0), \
		 SET4from3((to)[1], (from)[1], pad0), \
		 SET4from3((to)[2], (from)[2], pad0), \
		 FILLVEC3((to)[3], (pad0)), (to)[3][3] = (pad1))
#define M3XM4(to4,m3,m4)	\
		(_MXVcol3(to4,m3,m4,0), (to4)[3][0]=(m4)[3][0], \
		 _MXVcol3(to4,m3,m4,1), (to4)[3][1]=(m4)[3][1], \
		 _MXVcol3(to4,m3,m4,2), (to4)[3][2]=(m4)[3][2], \
		 _MXVcol3(to4,m3,m4,3), (to4)[3][3]=(m4)[3][3])
#define M4XM3(to4,m4,m3)	\
		(VXM3((to4)[0],(m4)[0],m3), (to4)[0][3]=(m4)[0][3], \
		 VXM3((to4)[1],(m4)[1],m3), (to4)[1][3]=(m4)[1][3], \
		 VXM3((to4)[2],(m4)[2],m3), (to4)[2][3]=(m4)[2][3], \
		 VXM3((to4)[3],(m4)[3],m3), (to4)[3][3]=(m4)[3][3])
#define VXVXVXV4(v0,v1,v2,v3)	\
		(_DET4(v0,v1,v2,v3,0,1,2,3))
#define DET4(m)	\
		(VXVXVXV4((m)[0],(m)[1],(m)[2],(m)[3]))
#define ADJOINT4(to,m)	\
		( _ADJOINTcol4(to,0,m,1,2,3), \
		 __ADJOINTcol4(to,1,m,0,2,3), \
		  _ADJOINTcol4(to,2,m,0,1,3), \
		 __ADJOINTcol4(to,3,m,0,1,2))
#define _ADJOINTcol4(to,col,m,i1,i2,i3)	\
		((to)[0][col] =  _DET3(m[i1],m[i2],m[i3], 1,2,3), \
		 (to)[1][col] = -_DET3(m[i1],m[i2],m[i3], 0,2,3), \
		 (to)[2][col] =  _DET3(m[i1],m[i2],m[i3], 0,1,3), \
		 (to)[3][col] = -_DET3(m[i1],m[i2],m[i3], 0,1,2))
#define __ADJOINTcol4(to,col,m,i1,i2,i3)	\
		((to)[0][col] = -_DET3(m[i1],m[i2],m[i3], 1,2,3), \
		 (to)[1][col] =  _DET3(m[i1],m[i2],m[i3], 0,2,3), \
		 (to)[2][col] = -_DET3(m[i1],m[i2],m[i3], 0,1,3), \
		 (to)[3][col] =  _DET3(m[i1],m[i2],m[i3], 0,1,2))
#define TRANSPOSE2safe(type,to,from) \
		do {type _vec_h_temp_[2][2]; \
		    TRANSPOSE2(_vec_h_temp_,from); \
		    SETMAT2(to, _vec_h_temp_); \
		} while (0)
#define TRANSPOSE2d(to,from) TRANSPOSE2safe(double,to,from)
#define TRANSPOSE2i(to,from) TRANSPOSE2safe(int,to,from)
#define TRANSPOSE2l(to,from) TRANSPOSE2safe(long,to,from)
#define TRANSPOSE2r(to,from) TRANSPOSE2safe(real,to,from)
#define MXM2safe(type,to,m1,m2) \
		do {type _vec_h_temp_[2][2]; \
		    MXM2(_vec_h_temp_,m1,m2); \
		    SETMAT2(to, _vec_h_temp_); \
		} while (0)
#define MXM2d(to,m1,m2) MXM2safe(double,to,m1,m2)
#define MXM2i(to,m1,m2) MXM2safe(int,to,m1,m2)
#define MXM2l(to,m1,m2) MXM2safe(long,to,m1,m2)
#define MXM2r(to,m1,m2) MXM2safe(real,to,m1,m2)
#define VXM2safe(type,to,v,m) \
		do {type _vec_h_temp_[2]; \
		    VXM2(_vec_h_temp_,v,m); \
		    SET2(to, _vec_h_temp_); \
		} while (0)
#define VXM2d(to,v,m) VXM2safe(double,to,v,m)
#define VXM2i(to,v,m) VXM2safe(int,to,v,m)
#define VXM2l(to,v,m) VXM2safe(long,to,v,m)
#define VXM2r(to,v,m) VXM2safe(real,to,v,m)
#define MXV2safe(type,to,m,v) \
		do {type _vec_h_temp_[2]; \
		    MXV2(_vec_h_temp_,m,v); \
		    SET2(to, _vec_h_temp_); \
		} while (0)
#define MXV2d(to,m,v) MXV2safe(double,to,m,v)
#define MXV2i(to,m,v) MXV2safe(int,to,m,v)
#define MXV2l(to,m,v) MXV2safe(long,to,m,v)
#define MXV2r(to,m,v) MXV2safe(real,to,m,v)
#define XV2safe(type,to,v1) \
		do {type _vec_h_temp_[2]; \
		    XV2(_vec_h_temp_,v1); \
		    SET2(to, _vec_h_temp_); \
		} while (0)
#define XV2d(to,v1) XV2safe(double,to,v1)
#define XV2i(to,v1) XV2safe(int,to,v1)
#define XV2l(to,v1) XV2safe(long,to,v1)
#define XV2r(to,v1) XV2safe(real,to,v1)
#define V2XM3safe(type,to2,v2,m3) \
		do {type _vec_h_temp_[2]; \
		    V2XM3(_vec_h_temp_,v2,m3); \
		    SET2(to2, _vec_h_temp_); \
		} while (0)
#define V2XM3d(to2,v2,m3) V2XM3safe(double,to2,v2,m3)
#define V2XM3i(to2,v2,m3) V2XM3safe(int,to2,v2,m3)
#define V2XM3l(to2,v2,m3) V2XM3safe(long,to2,v2,m3)
#define V2XM3r(to2,v2,m3) V2XM3safe(real,to2,v2,m3)
#define M3XV2safe(type,to2,m3,v2) \
		do {type _vec_h_temp_[2]; \
		    M3XV2(_vec_h_temp_,m3,v2); \
		    SET2(to2, _vec_h_temp_); \
		} while (0)
#define M3XV2d(to2,m3,v2) M3XV2safe(double,to2,m3,v2)
#define M3XV2i(to2,m3,v2) M3XV2safe(int,to2,m3,v2)
#define M3XV2l(to2,m3,v2) M3XV2safe(long,to2,m3,v2)
#define M3XV2r(to2,m3,v2) M3XV2safe(real,to2,m3,v2)
#define ADJOINT2safe(type,to,m) \
		do {type _vec_h_temp_[2][2]; \
		    ADJOINT2(_vec_h_temp_,m); \
		    SETMAT2(to, _vec_h_temp_); \
		} while (0)
#define ADJOINT2d(to,m) ADJOINT2safe(double,to,m)
#define ADJOINT2i(to,m) ADJOINT2safe(int,to,m)
#define ADJOINT2l(to,m) ADJOINT2safe(long,to,m)
#define ADJOINT2r(to,m) ADJOINT2safe(real,to,m)
#define TRANSPOSE3safe(type,to,from) \
		do {type _vec_h_temp_[3][3]; \
		    TRANSPOSE3(_vec_h_temp_,from); \
		    SETMAT3(to, _vec_h_temp_); \
		} while (0)
#define TRANSPOSE3d(to,from) TRANSPOSE3safe(double,to,from)
#define TRANSPOSE3i(to,from) TRANSPOSE3safe(int,to,from)
#define TRANSPOSE3l(to,from) TRANSPOSE3safe(long,to,from)
#define TRANSPOSE3r(to,from) TRANSPOSE3safe(real,to,from)
#define MXM3safe(type,to,m1,m2) \
		do {type _vec_h_temp_[3][3]; \
		    MXM3(_vec_h_temp_,m1,m2); \
		    SETMAT3(to, _vec_h_temp_); \
		} while (0)
#define MXM3d(to,m1,m2) MXM3safe(double,to,m1,m2)
#define MXM3i(to,m1,m2) MXM3safe(int,to,m1,m2)
#define MXM3l(to,m1,m2) MXM3safe(long,to,m1,m2)
#define MXM3r(to,m1,m2) MXM3safe(real,to,m1,m2)
#define VXM3safe(type,to,v,m) \
		do {type _vec_h_temp_[3]; \
		    VXM3(_vec_h_temp_,v,m); \
		    SET3(to, _vec_h_temp_); \
		} while (0)
#define VXM3d(to,v,m) VXM3safe(double,to,v,m)
#define VXM3i(to,v,m) VXM3safe(int,to,v,m)
#define VXM3l(to,v,m) VXM3safe(long,to,v,m)
#define VXM3r(to,v,m) VXM3safe(real,to,v,m)
#define MXV3safe(type,to,m,v) \
		do {type _vec_h_temp_[3]; \
		    MXV3(_vec_h_temp_,m,v); \
		    SET3(to, _vec_h_temp_); \
		} while (0)
#define MXV3d(to,m,v) MXV3safe(double,to,m,v)
#define MXV3i(to,m,v) MXV3safe(int,to,m,v)
#define MXV3l(to,m,v) MXV3safe(long,to,m,v)
#define MXV3r(to,m,v) MXV3safe(real,to,m,v)
#define VXV3safe(type,to,v1,v2) \
		do {type _vec_h_temp_[3]; \
		    VXV3(_vec_h_temp_,v1,v2); \
		    SET3(to, _vec_h_temp_); \
		} while (0)
#define VXV3d(to,v1,v2) VXV3safe(double,to,v1,v2)
#define VXV3i(to,v1,v2) VXV3safe(int,to,v1,v2)
#define VXV3l(to,v1,v2) VXV3safe(long,to,v1,v2)
#define VXV3r(to,v1,v2) VXV3safe(real,to,v1,v2)
#define M2XM3safe(type,to3,m2,m3) \
		do {type _vec_h_temp_[3][3]; \
		    M2XM3(_vec_h_temp_,m2,m3); \
		    SETMAT3(to3, _vec_h_temp_); \
		} while (0)
#define M2XM3d(to3,m2,m3) M2XM3safe(double,to3,m2,m3)
#define M2XM3i(to3,m2,m3) M2XM3safe(int,to3,m2,m3)
#define M2XM3l(to3,m2,m3) M2XM3safe(long,to3,m2,m3)
#define M2XM3r(to3,m2,m3) M2XM3safe(real,to3,m2,m3)
#define M3XM2safe(type,to3,m3,m2) \
		do {type _vec_h_temp_[3][3]; \
		    M3XM2(_vec_h_temp_,m3,m2); \
		    SETMAT3(to3, _vec_h_temp_); \
		} while (0)
#define M3XM2d(to3,m3,m2) M3XM2safe(double,to3,m3,m2)
#define M3XM2i(to3,m3,m2) M3XM2safe(int,to3,m3,m2)
#define M3XM2l(to3,m3,m2) M3XM2safe(long,to3,m3,m2)
#define M3XM2r(to3,m3,m2) M3XM2safe(real,to3,m3,m2)
#define V3XM4safe(type,to3,v3,m4) \
		do {type _vec_h_temp_[3]; \
		    V3XM4(_vec_h_temp_,v3,m4); \
		    SET3(to3, _vec_h_temp_); \
		} while (0)
#define V3XM4d(to3,v3,m4) V3XM4safe(double,to3,v3,m4)
#define V3XM4i(to3,v3,m4) V3XM4safe(int,to3,v3,m4)
#define V3XM4l(to3,v3,m4) V3XM4safe(long,to3,v3,m4)
#define V3XM4r(to3,v3,m4) V3XM4safe(real,to3,v3,m4)
#define M4XV3safe(type,to3,m4,v3) \
		do {type _vec_h_temp_[3]; \
		    M4XV3(_vec_h_temp_,m4,v3); \
		    SET3(to3, _vec_h_temp_); \
		} while (0)
#define M4XV3d(to3,m4,v3) M4XV3safe(double,to3,m4,v3)
#define M4XV3i(to3,m4,v3) M4XV3safe(int,to3,m4,v3)
#define M4XV3l(to3,m4,v3) M4XV3safe(long,to3,m4,v3)
#define M4XV3r(to3,m4,v3) M4XV3safe(real,to3,m4,v3)
#define ADJOINT3safe(type,to,m) \
		do {type _vec_h_temp_[3][3]; \
		    ADJOINT3(_vec_h_temp_,m); \
		    SETMAT3(to, _vec_h_temp_); \
		} while (0)
#define ADJOINT3d(to,m) ADJOINT3safe(double,to,m)
#define ADJOINT3i(to,m) ADJOINT3safe(int,to,m)
#define ADJOINT3l(to,m) ADJOINT3safe(long,to,m)
#define ADJOINT3r(to,m) ADJOINT3safe(real,to,m)
#define TRANSPOSE4safe(type,to,from) \
		do {type _vec_h_temp_[4][4]; \
		    TRANSPOSE4(_vec_h_temp_,from); \
		    SETMAT4(to, _vec_h_temp_); \
		} while (0)
#define TRANSPOSE4d(to,from) TRANSPOSE4safe(double,to,from)
#define TRANSPOSE4i(to,from) TRANSPOSE4safe(int,to,from)
#define TRANSPOSE4l(to,from) TRANSPOSE4safe(long,to,from)
#define TRANSPOSE4r(to,from) TRANSPOSE4safe(real,to,from)
#define MXM4safe(type,to,m1,m2) \
		do {type _vec_h_temp_[4][4]; \
		    MXM4(_vec_h_temp_,m1,m2); \
		    SETMAT4(to, _vec_h_temp_); \
		} while (0)
#define MXM4d(to,m1,m2) MXM4safe(double,to,m1,m2)
#define MXM4i(to,m1,m2) MXM4safe(int,to,m1,m2)
#define MXM4l(to,m1,m2) MXM4safe(long,to,m1,m2)
#define MXM4r(to,m1,m2) MXM4safe(real,to,m1,m2)
#define VXM4safe(type,to,v,m) \
		do {type _vec_h_temp_[4]; \
		    VXM4(_vec_h_temp_,v,m); \
		    SET4(to, _vec_h_temp_); \
		} while (0)
#define VXM4d(to,v,m) VXM4safe(double,to,v,m)
#define VXM4i(to,v,m) VXM4safe(int,to,v,m)
#define VXM4l(to,v,m) VXM4safe(long,to,v,m)
#define VXM4r(to,v,m) VXM4safe(real,to,v,m)
#define MXV4safe(type,to,m,v) \
		do {type _vec_h_temp_[4]; \
		    MXV4(_vec_h_temp_,m,v); \
		    SET4(to, _vec_h_temp_); \
		} while (0)
#define MXV4d(to,m,v) MXV4safe(double,to,m,v)
#define MXV4i(to,m,v) MXV4safe(int,to,m,v)
#define MXV4l(to,m,v) MXV4safe(long,to,m,v)
#define MXV4r(to,m,v) MXV4safe(real,to,m,v)
#define VXVXV4safe(type,to,v1,v2,v3) \
		do {type _vec_h_temp_[4]; \
		    VXVXV4(_vec_h_temp_,v1,v2,v3); \
		    SET4(to, _vec_h_temp_); \
		} while (0)
#define VXVXV4d(to,v1,v2,v3) VXVXV4safe(double,to,v1,v2,v3)
#define VXVXV4i(to,v1,v2,v3) VXVXV4safe(int,to,v1,v2,v3)
#define VXVXV4l(to,v1,v2,v3) VXVXV4safe(long,to,v1,v2,v3)
#define VXVXV4r(to,v1,v2,v3) VXVXV4safe(real,to,v1,v2,v3)
#define M3XM4safe(type,to4,m3,m4) \
		do {type _vec_h_temp_[4][4]; \
		    M3XM4(_vec_h_temp_,m3,m4); \
		    SETMAT4(to4, _vec_h_temp_); \
		} while (0)
#define M3XM4d(to4,m3,m4) M3XM4safe(double,to4,m3,m4)
#define M3XM4i(to4,m3,m4) M3XM4safe(int,to4,m3,m4)
#define M3XM4l(to4,m3,m4) M3XM4safe(long,to4,m3,m4)
#define M3XM4r(to4,m3,m4) M3XM4safe(real,to4,m3,m4)
#define M4XM3safe(type,to4,m4,m3) \
		do {type _vec_h_temp_[4][4]; \
		    M4XM3(_vec_h_temp_,m4,m3); \
		    SETMAT4(to4, _vec_h_temp_); \
		} while (0)
#define M4XM3d(to4,m4,m3) M4XM3safe(double,to4,m4,m3)
#define M4XM3i(to4,m4,m3) M4XM3safe(int,to4,m4,m3)
#define M4XM3l(to4,m4,m3) M4XM3safe(long,to4,m4,m3)
#define M4XM3r(to4,m4,m3) M4XM3safe(real,to4,m4,m3)
#define ADJOINT4safe(type,to,m) \
		do {type _vec_h_temp_[4][4]; \
		    ADJOINT4(_vec_h_temp_,m); \
		    SETMAT4(to, _vec_h_temp_); \
		} while (0)
#define ADJOINT4d(to,m) ADJOINT4safe(double,to,m)
#define ADJOINT4i(to,m) ADJOINT4safe(int,to,m)
#define ADJOINT4l(to,m) ADJOINT4safe(long,to,m)
#define ADJOINT4r(to,m) ADJOINT4safe(real,to,m)
#endif /* VEC_H */
