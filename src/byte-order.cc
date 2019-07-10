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

#include "rcdcap/byte-order.ii"

namespace RCDCap
{
template class NetworkByteOrderBitfield<uint8, 4, 4>;
template class NetworkByteOrderBitfield<uint16, 1, 1, 1, 1, 1, 3, 5, 3>;
template class NetworkByteOrderBitfield<uint16, 4, 12>;
template class NetworkByteOrderBitfield<uint32, 8, 3, 1, 12, 8>;
template class NetworkByteOrderBitfield<uint16, 3, 1, 12>;
template class NetworkByteOrderBitfield<uint16, 3, 13>;
template class NetworkByteOrderBitfield<uint16, 3, 1, 1, 1, 10>;
template class NetworkByteOrderBitfield<uint32, 4, 8, 20>;
template class NetworkByteOrderBitfield<uint32, 8, 24>;

template class NetworkByteOrder<bool>;
template class NetworkByteOrder<float>;
template class NetworkByteOrder<double>;
template class NetworkByteOrder<uint8>;
template class NetworkByteOrder<uint16>;
template class NetworkByteOrder<uint32>;
template class NetworkByteOrder<uint64>;
template class NetworkByteOrder<EtherType>;
template class NetworkByteOrder<ProtocolType>;
template class NetworkByteOrder<ARPOpcode>;
template class NetworkByteOrder<ARPHardwareType>;
template class NetworkByteOrder<DHCPOptionTag>;
template class NetworkByteOrder<ICMPv6MessageType>;
template class NetworkByteOrder<DHCPv6OptionCode>;
template class NetworkByteOrder<NDPOption>;
}