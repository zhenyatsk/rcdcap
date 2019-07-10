/*   RCDCap
 *   Copyright (C) 2012  Zdravko Velinov
 *
 *   This program is free software: you can redistribute it and/or modify
 *   it under the terms of the GNU General Public License as published by
 *   the Free Software Foundation, either version 3 of the License, or
 *   (at your option) any later version.
 *
 *   This program is distributed in the hope that it will be useful,
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *   GNU General Public License for more details.
 *
 *   You should have received a copy of the GNU General Public License
 *   along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#ifndef _RCDCAP_TYPES_HH_
#define _RCDCAP_TYPES_HH_

#include "rcdcap/global.hh"

#ifdef _WIN32
#   define WIN32_LEAN_AND_MEAN 1
#   include <windows.h>
#else
#   include <stdint.h>
#   include <inttypes.h>
#endif

namespace RCDCap
{
//! Fundamental data type that is representing a 8-bit integer.
typedef char                int8;

//! Fundamental data type that is representing a 8-bit unsigned integer.
typedef unsigned char       uint8;

//! Fundamental data type that is representing a 16-bit integer.
typedef short               int16;

//! Fundamental data type that is representing a 16-bit unsigned integer.
typedef unsigned short      uint16;
#ifdef _WIN32

//! Fundamental data type that is representing a 32-bit integer.
typedef INT32               int32;

//! Fundamental data type that is representing a 32-bit unsigned integer.
typedef UINT32              uint32;

//! Fundamental data type that is representing a 64-bit integer.
typedef INT64               int64;

//! Fundamental data type that is representing a 64-bit unsigned integer.
typedef UINT64              uint64;
#else
//! Fundamental data type that is representing a 32-bit integer.
typedef int32_t             int32;

//! Fundamental data type that is representing a 32-bit unsigned integer.
typedef uint32_t            uint32;

//! Fundamental data type that is representing a 64-bit integer.
typedef int64_t             int64;

//! Fundamental data type that is representing a 64-bit unsigned integer.
typedef uint64_t            uint64;
#endif
}

#endif /* _RCDCAP_TYPES_HH_ */