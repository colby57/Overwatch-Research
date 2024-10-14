#pragma once
#include <chrono>
#include <cstdint>
#include <limits>
#include <stdexcept>

namespace obfuscator
{
     constexpr uint64_t prime  = 0xdeadc0dedeadbeef;
     constexpr uint64_t offset = 0x1904a9401904a940;

     constexpr uint64_t random( uint64_t x )
     {
          return ( x ^ prime ) * offset;
     }

     constexpr uint64_t compile_time_seed( )
     {
          return static_cast<uint64_t>( __TIME__[0] ) | ( static_cast<uint64_t>( __TIME__[1] ) << 8 ) |
                 ( static_cast<uint64_t>( __TIME__[3] ) << 16 ) | ( static_cast<uint64_t>( __TIME__[4] ) << 24 ) |
                 ( static_cast<uint64_t>( __TIME__[6] ) << 32 ) | ( static_cast<uint64_t>( __TIME__[7] ) << 40 );
     }

     template <uint64_t X, uint64_t key = random( compile_time_seed( ) )>
     struct obfuscated_constant
     {
          static constexpr uint64_t random1     = random( X ^ key );
          static constexpr uint64_t random2     = random( random1 );
          static constexpr uint64_t random3     = random( random2 );
          static constexpr uint64_t crypted_val = ( ( ( X ^ random1 ) + random2 ) ^ random3 ) + key;

          __forceinline static uint64_t decrypt( )
          {
               uint64_t v = crypted_val;
               v -= key;
               v ^= random3;
               v -= random2;
               v ^= random1;
               return v;
          }
     };

     template <uint64_t X, uint64_t key = random( compile_time_seed( ) )>
     uint64_t obfuscate( )
     {
          return obfuscated_constant<X, key>::decrypt( );
     }
} // namespace obfuscator

#define OBFUSCATE( x ) obfuscator::obfuscate<x>( )
