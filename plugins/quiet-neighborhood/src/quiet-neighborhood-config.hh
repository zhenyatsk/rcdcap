/*   RCDCap
 *   Copyright (C) 2013  Zdravko Velinov
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

// Uncomment the options that you want to use. However, most people
// would be happy with the default options.

// Disables logging for profiling purposes.
#define DISABLE_QUIET_NEIGHBORHOOD_LOGGING

// The hashing function used by the network cache. The experiments
// point out that it is better to use faster function than one with
// better distribution. So the regular finalizer is sufficient for
// IPv4. In the case of IPv6 something else might get implemented
// when someone starts to use it for local networks.
#define NETWORK_CACHE_HASH_FUNCTION MURMURHASH3_FAST_FUNCTION
//#define NETWORK_CACHE_HASH_FUNCTION MURMURHASH3_FUNCTION
//#define NETWORK_CACHE_HASH_FUNCTION XXHASH_FUNCTION