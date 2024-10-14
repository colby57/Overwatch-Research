#pragma once

// clang-format off
#include <windows.h>
#include <cstdint>
#include <intrin.h>
#include <stdio.h>
#include <vector>
// clang-format on

namespace warden
{
     namespace veh
     {
          struct s_counter
          {
               volatile std::uint32_t value;
               std::uint32_t          base;
               std::uint32_t          max;
          };

          std::vector<s_counter> counters   = { { 0, 0x324, 0x7E0 } };
          HMODULE                cur_module = nullptr;

          bool check_time( s_counter& counter )
          {
               const auto now           = __rdtsc( );
               const auto random_offset = now & 0x3FF;

               if ( counter.value < ( counter.base + random_offset ) && counter.value < counter.max )
               {
                    counter.value++;
                    return true;
               }

               return false;
          }

          bool is_address_in_module( void* address )
          {
               if ( !cur_module )
               {
                    cur_module = GetModuleHandle( nullptr );
               }

               MODULEINFO module_info;
               if ( GetModuleInformation( GetCurrentProcess( ), cur_module, &module_info, sizeof( module_info ) ) )
               {
                    return (uintptr_t) address >= (uintptr_t) module_info.lpBaseOfDll &&
                           (uintptr_t) address < ( (uintptr_t) module_info.lpBaseOfDll + module_info.SizeOfImage );
               }
               return false;
          }

          std::uint32_t exception_handler( EXCEPTION_POINTERS* exception )
          {
               const auto code = exception->ExceptionRecord->ExceptionCode;
               printf( "Exception 0x%X handled at 0x%p\n", code, exception->ContextRecord->Rip );

               if ( code == EXCEPTION_SINGLE_STEP || code == EXCEPTION_BREAKPOINT || code == EXCEPTION_PRIV_INSTRUCTION )
               {
                    if ( !is_address_in_module( (void*) exception->ContextRecord->Rip ) )
                    {
                         exception->ContextRecord->EFlags &= 0x100;
                         return EXCEPTION_CONTINUE_EXECUTION;
                    }

                    if ( exception->ContextRecord->Dr7 != 0 )
                    {
                         exception->ContextRecord->Rsp ^= 0xdeadc0de;
                         printf( "Detected Dr7 = 0x%X\n", exception->ContextRecord->Dr7 );
                         return EXCEPTION_CONTINUE_SEARCH;
                    }

                    bool all_checks_passed = true;
                    for ( size_t i = 0; i < counters.size( ); ++i )
                    {
                         if ( !check_time( counters[i] ) )
                         {
                              all_checks_passed = false;
                              printf( "Failed check %zu: 0x%X\n", i + 1, counters[i].value );
                              break;
                         }
                         printf( "Passed check %zu: 0x%X\n", i + 1, counters[i].value );
                    }

                    if ( all_checks_passed )
                    {
                         exception->ContextRecord->EFlags |= 0x100;

                         std::uint8_t offset;
                         switch ( code )
                         {
                         case EXCEPTION_BREAKPOINT:
                              offset = 1;
                              if ( counters.size( ) < 5 )
                              {
                                   counters.push_back( { 0, 0x200 + (std::uint32_t) counters.size( ) * 0x100, 0x7E0 } );
                              }
                              break;
                         case EXCEPTION_SINGLE_STEP:
                              offset = 0;
                              break;
                         case EXCEPTION_PRIV_INSTRUCTION:
                              offset = 2;
                              break;
                         default:
                              return EXCEPTION_CONTINUE_SEARCH;
                         }

                         printf( "Passed all %zu checks\n", counters.size( ) );
                         exception->ContextRecord->Rip += offset;

                         return EXCEPTION_CONTINUE_EXECUTION;
                    }
                    else
                    {
                         return EXCEPTION_CONTINUE_SEARCH;
                    }
               }
               return EXCEPTION_CONTINUE_SEARCH;
          }

          void install( )
          {
               AddVectoredExceptionHandler( 1, (PVECTORED_EXCEPTION_HANDLER) exception_handler );
          }

          void uninstall( )
          {
               RemoveVectoredExceptionHandler( (PVECTORED_EXCEPTION_HANDLER) exception_handler );
          }
     } // namespace veh
} // namespace warden
