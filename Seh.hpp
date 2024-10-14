#pragma once

#include <excpt.h>
#include <stdexcept>
#include <type_traits>
#include <windows.h>

namespace seh
{
     template <typename R, typename... Args>
     struct FunctionTraits
     {
          using stdcall_type = R( __stdcall* )( Args... );
          using cdecl_type   = R( __cdecl* )( Args... );
     };

     template <typename Func, typename... Args>
     auto call( Func&& func, Args&&... args ) -> decltype( func( std::forward<Args>( args )... ) )
     {
          using ReturnType = decltype( func( std::forward<Args>( args )... ) );
          ReturnType result{ };

          __try
          {
               __debugbreak( );
          }
          __except ( EXCEPTION_EXECUTE_HANDLER )
          {
               if constexpr ( std::is_same_v<ReturnType, void> )
               {
                    func( std::forward<Args>( args )... );
               }
               else
               {
                    result = func( std::forward<Args>( args )... );
               }
          }

          return result;
     }
} // namespace seh
