#pragma once

// clang-format off
#include <cstdint>
#include <cstring>
#include <iostream>
#include <windows.h>
#include <Psapi.h>
// clang-format on

namespace warden
{
     namespace remap
     {
          using RemapFunction = void ( * )( void* original_base, std::size_t size, void* new_base );

          void __declspec( noinline ) do_remap( void* original_base, SIZE_T size, void* new_base )
          {
               const auto file =
                   CreateFileMappingA( INVALID_HANDLE_VALUE, nullptr, PAGE_EXECUTE_READWRITE, 0, static_cast<DWORD>( size ), nullptr );

               if ( !file )
               {
                    return;
               }

               if ( !UnmapViewOfFile( original_base ) )
               {
                    CloseHandle( file );
                    return;
               }

               void* mapped_base = MapViewOfFileEx( file, FILE_MAP_ALL_ACCESS | FILE_MAP_EXECUTE, 0, 0, size, original_base );
               if ( !mapped_base )
               {
                    printf( "Failed to map view of file at original address." );
                    CloseHandle( file );
                    return;
               }

               // Copy the content from our new allocation to the mapped view
               std::memcpy( mapped_base, new_base, size );

               mapped_base = MapViewOfFileEx( file, FILE_MAP_READ | FILE_MAP_EXECUTE, 0, 0, size, mapped_base );

               printf( "Remap successful.\n" );
               CloseHandle( file );
          }

          void __declspec( noinline ) remap_trampoline( )
          {
               auto base = GetModuleHandle( nullptr );

               MODULEINFO module_info;
               if ( !GetModuleInformation( (HANDLE) -1, base, &module_info, sizeof( module_info ) ) )
               {
                    std::printf( "Failed to get module information." );
                    return;
               }

               void* new_base = VirtualAlloc( nullptr, module_info.SizeOfImage, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE );
               if ( !new_base )
               {
                    std::printf( "Failed to allocate memory for remapping." );
                    return;
               }

               // Copy the module to the new location
               std::memcpy( new_base, module_info.lpBaseOfDll, module_info.SizeOfImage );

               // Calculate the offset to the do_remap function in the new allocation
               auto offset     = reinterpret_cast<uintptr_t>( do_remap ) - reinterpret_cast<uintptr_t>( base );
               auto remap_func = reinterpret_cast<RemapFunction>( reinterpret_cast<uintptr_t>( new_base ) + offset );

               // Call the remapping function from the new allocation
               remap_func( module_info.lpBaseOfDll, module_info.SizeOfImage, new_base );

               VirtualFree( new_base, 0, MEM_RELEASE );
          }

     } // namespace remap
} // namespace warden
