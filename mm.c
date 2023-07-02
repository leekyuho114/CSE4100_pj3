/*
 * mm-naive.c - The fastest, least memory-efficient malloc package.
 * 
 * In this naive approach, a block is allocated by simply incrementing
 * the brk pointer.  A block is pure payload. There are no headers or
 * footers.  Blocks are never coalesced or reused. Realloc is
 * implemented directly using mm_malloc and mm_free.
 *
 * NOTE TO STUDENTS: Replace this header comment with your own header
 * comment that gives a high level description of your solution.
 */
#include <stdio.h>
#include <stdlib.h>
#include <assert.h>
#include <unistd.h>
#include <string.h>

#include "mm.h"
#include "memlib.h"

/*********************************************************
 * NOTE TO STUDENTS: Before you do anything else, please
 * provide your information in the following struct.
 ********************************************************/
team_t team = {
    /* Your student ID */
    "20191617",
    /* Your full name*/
    "Kyuho Lee",
    /* Your email address */
    "rbgh0114@sogang.ac.kr",
};

#define WSIZE 4
#define DSIZE 8
#define CHUNKSIZE (1<<10) // heap extend size

#define MAX(x,y) ((x) > (y) ? (x):(y))

#define PACK(size,alloc) ((size) | (alloc))
#define GET(p) (*(unsigned int*)(p)) //void* 이므로 형변환, p word read
#define PUT(p,val) (*(unsigned int*)(p) =(val)) // p word  write

#define GET_SIZE(p) (GET(p) & ~0x7)
#define GET_ALLOC(p) (GET(p) & 0x1) // 주소 p에 있는 header or footer 할당 비트 return

#define HDRP(bp) ((char*)(bp) - WSIZE)
#define FTRP(bp) ((char*)(bp) + GET_SIZE(HDRP(bp)) - DSIZE)

#define NEXT_BLKP(bp) ((char*)(bp) + GET_SIZE((char*)(bp)-WSIZE))
#define PREV_BLKP(bp) ((char*)(bp) - GET_SIZE((char*)(bp)-DSIZE))
//next와 prev는 bp 주소 반환, 포인터끼리 이어진게 아님
#define NEXT_FREE_PTR(bp) (*(void**)(bp+WSIZE)) // 이후 블록 bp 주소값
#define PREV_FREE_PTR(bp) (*(void**)(bp)) // 이전 블록 bp 주소값

static char *heap_listp = 0;
static char *free_listp = 0; // free block list
//next fit일 경우
static void *extend_heap(size_t words);
static void place(void *bp, size_t asize);
static void *find_fit(size_t asize);
static void *coalesce(void *bp);
static void insert_free(void *bp);
static void remove_free(void *bp);
/* 
 * mm_init - initialize the malloc package.
 */
int mm_init(void)
{
    if ((heap_listp = mem_sbrk(6*WSIZE)) == (void *)-1) // sbrk fail
        return -1;
    PUT(heap_listp, 0); //padding
    PUT(heap_listp + (1*WSIZE), PACK(DSIZE*2, 1)); //prologue header
    PUT(heap_listp + (2*WSIZE), NULL); //prologue prev free pointer
    PUT(heap_listp + (3*WSIZE), NULL); //prologue next free pointer
    PUT(heap_listp + (4*WSIZE), PACK(DSIZE*2, 1)); //prologue footer
    PUT(heap_listp + (5*WSIZE), PACK(0, 1)); // epilogue header
    free_listp = heap_listp + DSIZE; // free list

    if (extend_heap(CHUNKSIZE/WSIZE) == NULL) //초기 가용블럭 생성
        return -1;
    return 0;
}

void *mm_malloc(size_t size)
{
    size_t asize;      // Adjusted size
    size_t extendsize;
    char *bp;

    if (size == 0)
        return NULL;

    if (size <= DSIZE)
        asize = 2*DSIZE;
    else // 요청한 size를 word 단위로 변환
        asize = DSIZE * ((size + (DSIZE) + (DSIZE-1)) / DSIZE); 
    // find_fit으로 가용블록을 가용리스트에서 검색, place로 배치
    if ((bp = find_fit(asize)) != NULL) {
        place(bp, asize); 
        return bp;
    }
    //no fit found 일때, heap 연장
    extendsize = MAX(asize,CHUNKSIZE);  
    if ((bp = extend_heap(extendsize/WSIZE)) == NULL)  
        return NULL;
    place(bp, asize); 
    return bp;
}

void mm_free(void *ptr)
{
    if (ptr == 0) 
        return;

    size_t size = GET_SIZE(HDRP(ptr));

    PUT(HDRP(ptr), PACK(size, 0));
    PUT(FTRP(ptr), PACK(size, 0));
    coalesce(ptr);
}
static void *coalesce(void *bp)
{
    size_t next_alloc = GET_ALLOC(HDRP(NEXT_BLKP(bp)));
    size_t prev_alloc = GET_ALLOC(FTRP(PREV_BLKP(bp)));
    size_t size = GET_SIZE(HDRP(bp));
    // case 1 : no merge
    if (prev_alloc && !next_alloc){      // case 2 : next merge
        remove_free(NEXT_BLKP(bp));
        size += GET_SIZE(HDRP(NEXT_BLKP(bp)));
        PUT(HDRP(bp), PACK(size, 0));
        PUT(FTRP(bp), PACK(size,0));
    }
    else if (!prev_alloc && next_alloc) { // case 3 : prev merge
        remove_free(PREV_BLKP(bp));
        size += GET_SIZE(HDRP(PREV_BLKP(bp)));
        PUT(FTRP(bp), PACK(size, 0)); 
        PUT(HDRP(PREV_BLKP(bp)), PACK(size, 0));
        bp = PREV_BLKP(bp);
    }
    else if (!prev_alloc && !next_alloc){     // case 4 : next, prev
        remove_free(PREV_BLKP(bp));
        remove_free(NEXT_BLKP(bp));
        size += GET_SIZE(HDRP(PREV_BLKP(bp))) + 
            GET_SIZE(FTRP(NEXT_BLKP(bp)));
        PUT(HDRP(PREV_BLKP(bp)), PACK(size, 0));
        PUT(FTRP(NEXT_BLKP(bp)), PACK(size, 0));
        bp = PREV_BLKP(bp);
    }
    insert_free(bp); // free list에 insert
    return bp;
}

void *mm_realloc(void *ptr, size_t size)
{
    void *oldptr = ptr;
    void *newptr;
    size_t copySize;
    newptr = mm_malloc(size);
    if(newptr == NULL) {
        return NULL;
    }
    // If size == 0 이면 free와 동일하게 동작
    if(size == 0) {
        mm_free(ptr); 
        return 0;
    }
    // 이미 null이면 malloc과 동일
    if(ptr == NULL) {
        return mm_malloc(size);
    }
    // oldsize copy
    copySize = GET_SIZE(HDRP(oldptr)); // 원래 사이즈 저장
    if(size < copySize){ // 요청 size가 더작다면 기존 사이즈 줄임
         copySize = size;
    }
    memcpy(newptr, oldptr, copySize);
    mm_free(oldptr);//old는 free

    return newptr;
}
static void *extend_heap(size_t words){
    char *bp;
    size_t size;
    size = (words % 2) ? (words+1) * WSIZE : words * WSIZE; // 짝수개수로 유지
    if ((long)(bp = mem_sbrk(size)) == -1){
        return NULL; 
    }
    // 새 free block의 header footer 후 epilogue
    PUT(HDRP(bp), PACK(size, 0));
    PUT(FTRP(bp), PACK(size, 0));
    PUT(HDRP(NEXT_BLKP(bp)), PACK(0, 1)); // epilogue 뒤로 밀어넣음

    /* Coalesce if the previous block was free */
    return coalesce(bp);
}
static void place(void *bp, size_t asize) 
{
    size_t csize = GET_SIZE(HDRP(bp));   
    remove_free(bp); // place하며 remove
    if ((csize - asize) >= (2*DSIZE)) { //할당 후 나머지공간 2*DSiZE 이상일 경우, 나머지공간 free 공간으로만듦
        PUT(HDRP(bp), PACK(asize, 1));
        PUT(FTRP(bp), PACK(asize, 1));
        bp = NEXT_BLKP(bp);
        PUT(HDRP(bp), PACK(csize-asize, 0));
        PUT(FTRP(bp), PACK(csize-asize, 0));
        insert_free(bp);
    }
    else {  // 할당 후 나머지공간 2*DSiZE보다 작을 경우
        PUT(HDRP(bp), PACK(csize, 1));
        PUT(FTRP(bp), PACK(csize, 1));
    }
}
static void *find_fit(size_t asize)
{
    void *bp;
    for (bp = free_listp; GET_ALLOC(HDRP(bp)) != 1; bp = NEXT_FREE_PTR(bp)) {
        if (asize <= GET_SIZE(HDRP(bp))) {
            return bp;
        }
    }
    return NULL;
}
//free list insert
static void insert_free(void *bp){
    PREV_FREE_PTR(bp) = NULL;
    NEXT_FREE_PTR(bp) = free_listp;  
    PREV_FREE_PTR(free_listp) =bp;
    free_listp = bp; 
}
//free list remove
static void remove_free(void *bp){
    if(bp == free_listp){ // remove first block
	    PREV_FREE_PTR(NEXT_FREE_PTR(bp)) = NULL;
        free_listp = NEXT_FREE_PTR(bp);
    }
    else{ // removing both prev, next
        NEXT_FREE_PTR(PREV_FREE_PTR(bp)) = NEXT_FREE_PTR(bp); 
	    PREV_FREE_PTR(NEXT_FREE_PTR(bp)) = PREV_FREE_PTR(bp);
    }
}