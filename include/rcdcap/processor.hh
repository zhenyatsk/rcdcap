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

#ifndef _RCDCAP_PROCESSOR_HH_
#define _RCDCAP_PROCESSOR_HH_

#include "rcdcap/global.hh"
#include "rcdcap/source.hh"
#include "rcdcap/sink.hh"

#include <vector>
#include <memory>

namespace RCDCap
{
/*! \brief Processor base class.
 *
 *  The classes that inherit from that base class are used to process data, which is being captured
 *  from a particular DataSource, and write it to the specified Sink object.
 */
class DLL_EXPORT Processor: public Source, public Sink
{
public:
    //! Default constructor.
    Processor()=default;
    
    //! Destructor.
    virtual ~Processor() {}
};
}

#endif /* _RCDCAP_PROCESSOR_HH_ */
