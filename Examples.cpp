#include "AntiDebug.hpp"
#include "ConstantObf.hpp"
#include "Remap.hpp"
#include "Seh.hpp"
#include "Veh.hpp"

int main( )
{
     // warden::veh::install( );
     // __debugbreak( );

     // warden::remap::remap_trampoline( );
     // warden::antidebug::init( );

     // auto res = warden::antidebug::check_debug_port( );
     // printf( "check_debug_port: %d\n", res );

     // res = warden::antidebug::check_process_flags( );
     // printf( "check_process_flags: %d\n", res );

     // res = warden::antidebug::hide_thread( );
     // printf( "hide_thread: %d\n", res );

     seh::call( MessageBoxA, nullptr, "Hello, World!", "Debug", 0 );

     const auto a = OBFUSCATE( 0xdeadbeefdeadbeef );
     seh::call( printf, "a: %p\n", a );

     return 0;
}
