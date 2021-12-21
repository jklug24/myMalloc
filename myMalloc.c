#include <errno.h>
#include <pthread.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "myMalloc.h"
#include "printing.h"

/* Due to the way assert() prints error messges we use out own assert function
 * for deteminism when testing assertions
 */
#ifdef TEST_ASSERT
  inline static void assert(int e) {
    if (!e) {
      const char * msg = "Assertion Failed!\n";
      write(2, msg, strlen(msg));
      exit(1);
    }
  }
#else
  #include <assert.h>
#endif

/*
 * Mutex to ensure thread safety for the freelist
 */
static pthread_mutex_t mutex;

/*
 * Array of sentinel nodes for the freelists
 */
header freelistSentinels[N_LISTS];

/*
 * Pointer to the second fencepost in the most recently allocated chunk from
 * the OS. Used for coalescing chunks
 */
header * lastFencePost;

/*
 * Pointer to maintian the base of the heap to allow printing based on the
 * distance from the base of the heap
 */ 
void * base;

/*
 * List of chunks allocated by  the OS for printing boundary tags
 */
header * osChunkList [MAX_OS_CHUNKS];
size_t numOsChunks = 0;

/*
 * direct the compiler to run the init function before running main
 * this allows initialization of required globals
 */
static void init (void) __attribute__ ((constructor));

// Helper functions for manipulating pointers to headers
static inline header * get_header_from_offset(void * ptr, ptrdiff_t off);
static inline header * get_left_header(header * h);
static inline header * ptr_to_header(void * p);

// Helper functions for allocating more memory from the OS
static inline void initialize_fencepost(header * fp, size_t left_size);
static inline void insert_os_chunk(header * hdr);
static inline void insert_fenceposts(void * raw_mem, size_t size);
static header * allocate_chunk(size_t size);

// Helper functions for freeing a block
static inline void deallocate_object(void * p);

// Helper functions for allocating a block
static inline header * allocate_object(size_t raw_size);
header * find_free(size_t size);

// Helper functions for verifying that the data structures are structurally 
// valid
static inline header * detect_cycles();
static inline header * verify_pointers();
static inline bool verify_freelist();
static inline header * verify_chunk(header * chunk);
static inline bool verify_tags();

static void init();

static bool isMallocInitialized;

/**
 * @brief Helper function to retrieve a header pointer from a pointer and an 
 *        offset
 *
 * @param ptr base pointer
 * @param off number of bytes from base pointer where header is located
 *
 * @return a pointer to a header offset bytes from pointer
 */
static inline header * get_header_from_offset(void * ptr, ptrdiff_t off) {
	return (header *)((char *) ptr + off);
}

/**
 * @brief Helper function to get the header to the right of a given header
 *
 * @param h original header
 *
 * @return header to the right of h
 */
header * get_right_header(header * h) {
	return get_header_from_offset(h, get_size(h));
}

/**
 * @brief Helper function to get the header to the left of a given header
 *
 * @param h original header
 *
 * @return header to the right of h
 */
inline static header * get_left_header(header * h) {
  return get_header_from_offset(h, -h->left_size);
}

/**
 * @brief Fenceposts are marked as always allocated and may need to have
 * a left object size to ensure coalescing happens properly
 *
 * @param fp a pointer to the header being used as a fencepost
 * @param left_size the size of the object to the left of the fencepost
 */
inline static void initialize_fencepost(header * fp, size_t left_size) {
	set_state(fp,FENCEPOST);
	set_size(fp, ALLOC_HEADER_SIZE);
	fp->left_size = left_size;
}

/**
 * @brief Helper function to maintain list of chunks from the OS for debugging
 *
 * @param hdr the first fencepost in the chunk allocated by the OS
 */
inline static void insert_os_chunk(header * hdr) {
  if (numOsChunks < MAX_OS_CHUNKS) {
    osChunkList[numOsChunks++] = hdr;
  }
}

/**
 * @brief given a chunk of memory insert fenceposts at the left and 
 * right boundaries of the block to prevent coalescing outside of the
 * block
 *
 * @param raw_mem a void pointer to the memory chunk to initialize
 * @param size the size of the allocated chunk
 */
inline static void insert_fenceposts(void * raw_mem, size_t size) {
  // Convert to char * before performing operations
  char * mem = (char *) raw_mem;

  // Insert a fencepost at the left edge of the block
  header * leftFencePost = (header *) mem;
  initialize_fencepost(leftFencePost, ALLOC_HEADER_SIZE);

  // Insert a fencepost at the right edge of the block
  header * rightFencePost = get_header_from_offset(mem, size - ALLOC_HEADER_SIZE);
  initialize_fencepost(rightFencePost, size - 2 * ALLOC_HEADER_SIZE);
}

/**
 * @brief Allocate another chunk from the OS and prepare to insert it
 * into the free list
 *
 * @param size The size to allocate from the OS
 *
 * @return A pointer to the allocable block in the chunk (just after the 
 * first fencpost)
 */
static header * allocate_chunk(size_t size) {
  void * mem = sbrk(size);
  
  insert_fenceposts(mem, size);
  header * hdr = (header *) ((char *)mem + ALLOC_HEADER_SIZE);
  set_state(hdr, UNALLOCATED);
  set_size(hdr, size - 2 * ALLOC_HEADER_SIZE);
  hdr->left_size = ALLOC_HEADER_SIZE;
  return hdr;
}

/**
 * @brief Helper allocate an object given a raw request size from the user
 *
 * @param raw_size number of bytes the user needs
 *
 * @return A block satisfying the user's request
 */
static inline header * allocate_object(size_t raw_size) {
  // TODO implement allocation
  if (raw_size == 0) {
    return NULL;
  }
  size_t req_size = (raw_size + 7) & ~0x7;
  size_t actual_size = (req_size + ALLOC_HEADER_SIZE > sizeof(header)) ? 
          (req_size + ALLOC_HEADER_SIZE) : sizeof(header);
  size_t alloc_size = actual_size - ALLOC_HEADER_SIZE;

  header * free_block = find_free(alloc_size);
  size_t free_size = get_size(free_block);
  size_t rem_size = free_size - actual_size;
  // split block when necessary and set occupied flag
  if (rem_size >= sizeof(header)) {
    // Split free block and set the right portion of the free block
    // as allocated
    header * right_free = get_header_from_offset(free_block, rem_size);
    right_free->left_size = rem_size;
    set_size_and_state(right_free, actual_size, ALLOCATED);
    set_size(free_block, rem_size);
    get_right_header(right_free)->left_size=actual_size;

    // move the new free chunk to the right sentinel if necessary
    rem_size -= ALLOC_HEADER_SIZE;
    if ((rem_size / 8) - 1 < (N_LISTS - 1)) {
      free_block->prev->next = free_block->next;
      free_block->next->prev = free_block->prev;

      free_block->prev = &freelistSentinels[(rem_size / 8) - 1];
      free_block->next = freelistSentinels[(rem_size / 8) - 1].next;

      free_block->prev->next = free_block;
      free_block->next->prev = free_block;
    }
    return (header *) right_free->data;

  } else {
    set_state(free_block, ALLOCATED);
    free_block->prev->next = free_block->next;
    free_block->next->prev = free_block->prev;
    return (header * ) free_block->data;
  }

}

header * find_free(size_t size) {
  int i = ((size  / 8) - 1 > N_LISTS - 1) ? (N_LISTS - 1) : ((size / 8) - 1);

  // Traverse Free Lists for one thats not empty
  while (i < N_LISTS - 1 &&
        freelistSentinels[i].next == &freelistSentinels[i]) {
    i++;
  }
  if (i == N_LISTS - 1) {
    
    //If the only avalible free list is the last one traverse the
    //last free list for a block large enough
    header * head = &freelistSentinels[i];
    header * curr = head->next;
    while (get_size(curr) < size && head != curr) {
      curr = curr->next;
    }

    if (head != curr) {
      // If there is a block in the last freelist large enough return it
      return curr;
    } else {
      // If there is not a block in the last freelist, create a new chunk
      header * new_chunk = allocate_chunk(ARENA_SIZE);

      // Check if the new chunk is adjacent to the last chunk
      if (get_header_from_offset(lastFencePost, get_size(lastFencePost)) ==
                      get_left_header(new_chunk)) {
        // Check if the last block in an adjacent chunk is allocated
        header * last_block = get_left_header(lastFencePost);
        if (get_state(last_block) == UNALLOCATED) {
          // If it isn't allocated merge it with the new chunk
          set_size(last_block, 
                get_size(last_block) + (2 * ALLOC_HEADER_SIZE) + get_size(new_chunk));
          lastFencePost = new_chunk + get_size(new_chunk);
          return last_block;
        } else {
          // If it is allocated merge the chunks by removing the adjacent fenceposts
          header * new_block = lastFencePost;
          set_size(new_block, 
                get_size(lastFencePost) + get_size(new_chunk) + new_chunk->left_size);
          lastFencePost = get_header_from_offset(new_block, get_size(new_block));
          lastFencePost->left_size = get_size(new_block);
          set_state(new_block, UNALLOCATED);
          new_block->prev = &freelistSentinels[N_LISTS - 1];
          new_block->next = freelistSentinels[N_LISTS - 1].next;
          new_block->prev->next = new_block;
          new_block->next->prev = new_block;
          return new_block;
        }
      } else {
        // If the new chunk is not adjacent, insert it into the freelist
        insert_os_chunk(get_left_header(new_chunk));
        new_chunk->next = freelistSentinels[N_LISTS - 1].next;
        new_chunk->prev = &freelistSentinels[N_LISTS - 1];
        new_chunk->next->prev = new_chunk;
        new_chunk->prev->next = new_chunk;

        lastFencePost = get_header_from_offset(new_chunk, get_size(new_chunk));
        return new_chunk;
      }
    }

  } else {
    return freelistSentinels[i].next;
  }

}

/**
 * @brief Helper to get the header from a pointer allocated with malloc
 *
 * @param p pointer to the data region of the block
 *
 * @return A pointer to the header of the block
 */
static inline header * ptr_to_header(void * p) {
  return (header *)((char *) p - ALLOC_HEADER_SIZE); //sizeof(header));
}

/**
 * @brief Helper to manage deallocation of a pointer returned by the user
 *
 * @param p The pointer returned to the user by a call to malloc
 */
static inline void deallocate_object(void * p) {
  if (p == NULL) {
    return;
  }

  header * hdr = ptr_to_header(p);
  if (get_state(hdr) == UNALLOCATED) {
    printf("Double Free Detected\n");
    assert(get_state(hdr) == ALLOCATED);
  }
  
  // Check to see if the block to the right can be coallesced
  header * right_block = get_header_from_offset(hdr, get_size(hdr));
  if (get_state(right_block) == UNALLOCATED) {
    size_t new_size = get_size(right_block) + get_size(hdr);
    set_size(hdr, new_size);
    get_header_from_offset(right_block, get_size(right_block))->left_size =  new_size;
    right_block->prev->next = right_block->next;
    right_block->next->prev = right_block->prev;
  }

  // Check to see if the block to the left can be coallesced
  header * left_block = get_left_header(hdr);
  if (get_state(left_block) == UNALLOCATED) {
    size_t free_size = get_size(hdr) + get_size(left_block);
    set_size(left_block, free_size);
    set_state(hdr, UNALLOCATED);
    size_t alloc_free_size = free_size - ALLOC_HEADER_SIZE;
    int i = ((alloc_free_size  / 8) - 1 > N_LISTS - 1) ?
            (N_LISTS - 1) : ((alloc_free_size / 8) - 1);
    
    left_block->prev->next = left_block->next;
    left_block->next->prev = left_block->prev;

    left_block->prev = &freelistSentinels[i];
    left_block->next = freelistSentinels[i].next;
    left_block->next->prev = left_block;
    left_block->prev->next = left_block;

    get_header_from_offset(left_block, free_size)->left_size = free_size;
  } else {
    // If the left block can't be coallesced, insert the 
    set_state(hdr, UNALLOCATED);
    size_t free_size = get_size(hdr) - ALLOC_HEADER_SIZE;
    int i = ((free_size  / 8) - 1 > N_LISTS - 1) ? (N_LISTS - 1) : ((free_size / 8) - 1);
    hdr->prev = &freelistSentinels[i];
    hdr->next = freelistSentinels[i].next;
    hdr->next->prev = hdr;
    hdr->prev->next = hdr;
  }
}

/**
 * @brief Helper to detect cycles in the free list
 * https://en.wikipedia.org/wiki/Cycle_detection#Floyd's_Tortoise_and_Hare
 *
 * @return One of the nodes in the cycle or NULL if no cycle is present
 */
static inline header * detect_cycles() {
  for (int i = 0; i < N_LISTS; i++) {
    header * freelist = &freelistSentinels[i];
    for (header * slow = freelist->next, * fast = freelist->next->next; 
         fast != freelist; 
         slow = slow->next, fast = fast->next->next) {
      if (slow == fast) {
        return slow;
      }
    }
  }
  return NULL;
}

/**
 * @brief Helper to verify that there are no unlinked previous or next pointers
 *        in the free list
 *
 * @return A node whose previous and next pointers are incorrect or NULL if no
 *         such node exists
 */
static inline header * verify_pointers() {
  for (int i = 0; i < N_LISTS; i++) {
    header * freelist = &freelistSentinels[i];
    for (header * cur = freelist->next; cur != freelist; cur = cur->next) {
      if (cur->next->prev != cur || cur->prev->next != cur) {
        return cur;
      }
    }
  }
  return NULL;
}

/**
 * @brief Verify the structure of the free list is correct by checkin for 
 *        cycles and misdirected pointers
 *
 * @return true if the list is valid
 */
static inline bool verify_freelist() {
  header * cycle = detect_cycles();
  if (cycle != NULL) {
    fprintf(stderr, "Cycle Detected\n");
    print_sublist(print_object, cycle->next, cycle);
    return false;
  }

  header * invalid = verify_pointers();
  if (invalid != NULL) {
    fprintf(stderr, "Invalid pointers\n");
    print_object(invalid);
    return false;
  }

  return true;
}

/**
 * @brief Helper to verify that the sizes in a chunk from the OS are correct
 *        and that allocated node's canary values are correct
 *
 * @param chunk AREA_SIZE chunk allocated from the OS
 *
 * @return a pointer to an invalid header or NULL if all header's are valid
 */
static inline header * verify_chunk(header * chunk) {
	if (get_state(chunk) != FENCEPOST) {
		fprintf(stderr, "Invalid fencepost\n");
		print_object(chunk);
		return chunk;
	}
	
	for (; get_state(chunk) != FENCEPOST; chunk = get_right_header(chunk)) {
		if (get_size(chunk)  != get_right_header(chunk)->left_size) {
			fprintf(stderr, "Invalid sizes\n");
			print_object(chunk);
			return chunk;
		}
	}
	
	return NULL;
}

/**
 * @brief For each chunk allocated by the OS verify that the boundary tags
 *        are consistent
 *
 * @return true if the boundary tags are valid
 */
static inline bool verify_tags() {
  for (size_t i = 0; i < numOsChunks; i++) {
    header * invalid = verify_chunk(osChunkList[i]);
    if (invalid != NULL) {
      return invalid;
    }
  }

  return NULL;
}

/**
 * @brief Initialize mutex lock and prepare an initial chunk of memory for allocation
 */
static void init() {
  // Initialize mutex for thread safety
  pthread_mutex_init(&mutex, NULL);

#ifdef DEBUG
  // Manually set printf buffer so it won't call malloc when debugging the allocator
  setvbuf(stdout, NULL, _IONBF, 0);
#endif // DEBUG

  // Allocate the first chunk from the OS
  header * block = allocate_chunk(ARENA_SIZE);

  header * prevFencePost = get_header_from_offset(block, -ALLOC_HEADER_SIZE);
  insert_os_chunk(prevFencePost);

  lastFencePost = get_header_from_offset(block, get_size(block));

  // Set the base pointer to the beginning of the first fencepost in the first
  // chunk from the OS
  base = ((char *) block) - ALLOC_HEADER_SIZE; //sizeof(header);

  // Initialize freelist sentinels
  for (int i = 0; i < N_LISTS; i++) {
    header * freelist = &freelistSentinels[i];
    freelist->next = freelist;
    freelist->prev = freelist;
  }

  // Insert first chunk into the free list
  header * freelist = &freelistSentinels[N_LISTS - 1];
  freelist->next = block;
  freelist->prev = block;
  block->next = freelist;
  block->prev = freelist;
}

/* 
 * External interface
 */
void * my_malloc(size_t size) {
  pthread_mutex_lock(&mutex);
  header * hdr = allocate_object(size); 
  pthread_mutex_unlock(&mutex);
  return hdr;
}

void * my_calloc(size_t nmemb, size_t size) {
  return memset(my_malloc(size * nmemb), 0, size * nmemb);
}

void * my_realloc(void * ptr, size_t size) {
  void * mem = my_malloc(size);
  memcpy(mem, ptr, size);
  my_free(ptr);
  return mem; 
}

void my_free(void * p) {
  pthread_mutex_lock(&mutex);
  deallocate_object(p);
  pthread_mutex_unlock(&mutex);
}

bool verify() {
  return verify_freelist() && verify_tags();
}
