#pragma once

#include <string_view>
#include <Windows.h>

namespace warden
{
     namespace antidebug
     {
          std::uint64_t ntdll = 0;

          typedef NTSTATUS( NTAPI* pNtSetInformationThread )( HANDLE, ULONG, PVOID, ULONG );
          typedef NTSTATUS( NTAPI* pNtQueryInformationProcess )( HANDLE, ULONG, PVOID, ULONG, PULONG );

          void init( )
          {
               // Hardcoded path to ntdll.dll
               constexpr std::wstring_view file_path = L"C:\\Windows\\System32\\ntdll.dll";

               HANDLE file_handle = CreateFileW( file_path.data( ), GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_DELETE, nullptr,
                                                 OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr );

               if ( file_handle == INVALID_HANDLE_VALUE )
               {
                    return;
               }

               LARGE_INTEGER file_size = { };
               if ( !GetFileSizeEx( file_handle, &file_size ) )
               {
                    CloseHandle( file_handle );
                    return;
               }

               LPVOID buffer =
                   VirtualAlloc( nullptr, static_cast<SIZE_T>( file_size.QuadPart ), MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE );

               if ( !buffer )
               {
                    CloseHandle( file_handle );
                    return;
               }

               DWORD bytes_read = 0;
               if ( !ReadFile( file_handle, buffer, static_cast<DWORD>( file_size.QuadPart ), &bytes_read, nullptr ) )
               {
                    VirtualFree( buffer, 0, MEM_RELEASE );
                    CloseHandle( file_handle );
                    return;
               }

               if ( bytes_read != file_size.QuadPart )
               {
                    VirtualFree( buffer, 0, MEM_RELEASE );
                    CloseHandle( file_handle );
                    return;
               }

               CloseHandle( file_handle );

               auto* dos_header = static_cast<IMAGE_DOS_HEADER*>( buffer );
               if ( dos_header->e_magic != IMAGE_DOS_SIGNATURE )
               {
                    VirtualFree( buffer, 0, MEM_RELEASE );
                    return;
               }

               auto* nt_headers = reinterpret_cast<IMAGE_NT_HEADERS*>( reinterpret_cast<uint8_t*>( buffer ) + dos_header->e_lfanew );
               if ( nt_headers->Signature != IMAGE_NT_SIGNATURE )
               {
                    VirtualFree( buffer, 0, MEM_RELEASE );
                    return;
               }

               ntdll = reinterpret_cast<std::uint64_t>( buffer );
               printf( "Ntdll loaded at: 0x%p.\n", reinterpret_cast<void*>( ntdll ) );
          }

          void* get_proc_address( const char* proc_name )
          {
               if ( !ntdll )
                    return nullptr;

               auto* dos_header = reinterpret_cast<IMAGE_DOS_HEADER*>( ntdll );
               auto* nt_headers = reinterpret_cast<IMAGE_NT_HEADERS*>( ntdll + dos_header->e_lfanew );

               auto* export_directory = reinterpret_cast<IMAGE_EXPORT_DIRECTORY*>(
                   ntdll + nt_headers->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress );

               auto* names     = reinterpret_cast<DWORD*>( ntdll + export_directory->AddressOfNames );
               auto* functions = reinterpret_cast<DWORD*>( ntdll + export_directory->AddressOfFunctions );
               auto* ordinals  = reinterpret_cast<WORD*>( ntdll + export_directory->AddressOfNameOrdinals );

               for ( DWORD i = 0; i < export_directory->NumberOfNames; ++i )
               {
                    const char* name = reinterpret_cast<const char*>( ntdll + names[i] );
                    if ( strcmp( name, proc_name ) == 0 )
                    {
                         return reinterpret_cast<void*>( ntdll + functions[ordinals[i]] );
                    }
               }

               return nullptr;
          }

          bool hide_thread( )
          {
               if ( !ntdll )
                    return false;

               auto NtSetInformationThread = reinterpret_cast<pNtSetInformationThread>( get_proc_address( "NtSetInformationThread" ) );

               if ( !NtSetInformationThread )
                    return false;

               return NtSetInformationThread( reinterpret_cast<HANDLE>( -2 ), 0x11, nullptr, 0 ) >= 0;
          }

          bool check_debug_port( )
          {
               if ( !ntdll )
                    return false;

               auto NtQueryInformationProcess =
                   reinterpret_cast<pNtQueryInformationProcess>( get_proc_address( "NtQueryInformationProcess" ) );

               if ( !NtQueryInformationProcess )
                    return false;

               ULONG64 debug_port    = 0;
               ULONG   return_length = 0;

               if ( NtQueryInformationProcess( reinterpret_cast<HANDLE>( -1 ), 0x7, &debug_port, sizeof( debug_port ), &return_length ) >=
                    0 )
               {
                    return debug_port != 0;
               }

               return false;
          }

          bool check_process_flags( )
          {
               if ( !ntdll )
                    return false;

               auto NtQueryInformationProcess =
                   reinterpret_cast<pNtQueryInformationProcess>( get_proc_address( "NtQueryInformationProcess" ) );

               if ( !NtQueryInformationProcess )
                    return false;

               ULONG debug_flags   = 0;
               ULONG return_length = 0;

               if ( NtQueryInformationProcess( reinterpret_cast<HANDLE>( -1 ), 0x1f, &debug_flags, sizeof( debug_flags ),
                                               &return_length ) >= 0 )
               {
                    return debug_flags == 0;
               }

               return false;
          }
     } // namespace antidebug
} // namespace warden
