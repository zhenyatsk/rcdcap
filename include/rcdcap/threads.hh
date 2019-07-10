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

#ifndef _RCDCAP_THREADS_HH_
#define _RCDCAP_THREADS_HH_

#include <atomic>

/*! \brief Spin lock object.
 * 
 *  It is used for performance critical parts that can't rely on the
 *  operating system mutex implementation. The actual lock does busy
 *  wait, so it might lead to resource starvation.
 */
class SpinLock
{
    //! The variable that is being used for locking the critical section.
    std::atomic_flag m_Flag;
public:
    //! Locks the critical section.
    void lock()
    {
        while(m_Flag.test_and_set(std::memory_order_acquire));
    }
    
    //! Tries to lock the critical section.
    bool try_lock()
    {
        return !m_Flag.test_and_set(std::memory_order_acquire);
    }
    
    //! Unlocks the critical section.
    void unlock()
    {
        m_Flag.clear(std::memory_order_release);
    }
};

#endif // _RCDCAP_THREADS_HH_