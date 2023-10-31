/* gcc -Wall -Wextra -o packet_buffer_tests packet_buffer_tests.c packet_buffer.c */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include "packet_buffer.h"


int main () {
    // tests for pbuf

    // create pbuf
    void *pbuf = pbuf_create(10, 10);

    uint8_t test1[10] = "1234";
    uint8_t test2[10] = "abcdefg";
    uint8_t test3[10] = "ABCDEF";

    uint32_t offset;
    uint16_t data_length;
    uint16_t video_width;
    uint16_t video_height;
    bool is_last_packet;
    uint32_t timestamp;

    // retrieve from position 0, should fail
    char * ptr_result;
    ptr_result = (char *) pbuf_retrieve(pbuf, 
        0,  /* test parameter*/
        &timestamp, &is_last_packet, 
        &offset, &video_width, &video_height,
        &data_length
    );
    if (ptr_result == NULL) {
        printf("test1 passed\n");
    }

    // retrieve from position 1, should fail
    ptr_result = (char *) pbuf_retrieve(pbuf, 
        1,  /* test parameter*/
        &timestamp, &is_last_packet, 
        &offset, &video_width, &video_height,
        &data_length
        );
    if (ptr_result == NULL) {
        printf("test2 passed\n");
    }

    // insert into position 0
    //                           num,ts, last,off,w, h, data, len
    int result = pbuf_insert(pbuf, 0, 1, true, 1, 1, 1, test1, 5);
    if (result == 0) {
        printf("test3 passed\n");
    }

    // insert into position 7
    //                        num,ts, last,off,w, h, data, len
    result = pbuf_insert(pbuf, 7, 10, true, 7, 8, 9, test2, 8);
    if (result == 0) {
        printf("test4 passed\n");
    }

    // insert AGAIN into position 7, no problem
    //                        num,ts, last,off,w, h, data, len
    result = pbuf_insert(pbuf, 7, 10, true, 7, 8, 9, test2, 8);
    if (result == 0) {
        printf("test4-BIS passed\n");
    }

    // insert into position 10
    //                        num, ts, last,off,w, h, data, len
    result = pbuf_insert(pbuf, 10, 10, true, 7, 8, 9, test3, 7);
    if (result == 0) {
        printf("test5 passed\n");
    }

    // retrieve from position 10, should pass
    ptr_result = (char *) pbuf_retrieve(pbuf, 
        10,  /* test parameter*/
        &timestamp, &is_last_packet, 
        &offset, &video_width, &video_height,
        &data_length
    );
    if (memcmp(ptr_result, test3, data_length) == 0 
         && data_length == 7  && offset == 7 && video_width == 8 
         && video_height == 9 && is_last_packet && timestamp == 10
    ) {
        printf("test6 passed\n");
    }
    else {
            printf("FAILED test6");
            printf("data is %s, should be %s\n", ptr_result, test3);
            // printf all the other values
            printf("offset is %d, should be 7\n", offset);  
            printf("data_length is %d, should be %ld\n", data_length, strlen(test3)+1);
            printf("video_width is %d, should be 8\n", video_width);
            printf("video_height is %d, should be 9\n", video_height);
            printf("is_last_packet is %d, should be 1\n", is_last_packet);
            printf("timestamp is %d, should be 10\n", timestamp);
            printf("test6 failed\n");
    }

    // retrieve from position 7, should pass
    ptr_result = (char *) pbuf_retrieve(pbuf, 
        7,  /* test parameter*/
        &timestamp, &is_last_packet, 
        &offset, &video_width, &video_height,
        &data_length
    );
    //                           num,ts, last,off,w, h, data, len
    // result = pbuf_insert(pbuf, 7, 10, true, 7, 8, 9, test2, 8);
    if (memcmp(ptr_result, test2, 6) == 0 && 
    data_length == strlen(test2) +1  && offset == 7 && video_width == 8 && video_height == 9 && is_last_packet && timestamp == 10) {
        printf("test7 passed\n");
    }
    else {
        printf("test7 failed, result is %d\n", result);
    }


    // repeat test 7, should pass
        // retrieve from position 7, should pass
    ptr_result = (char *) pbuf_retrieve(pbuf, 
        7,  /* test parameter*/
        &timestamp, &is_last_packet, 
        &offset, &video_width, &video_height,
        &data_length
    );
    //                           num,ts, last,off,w, h, data, len
    // result = pbuf_insert(pbuf, 7, 10, true, 7, 8, 9, test2, 8);
    if (memcmp(ptr_result, test2, 6) == 0 && 
    data_length == strlen(test2) +1  && offset == 7 && video_width == 8 && video_height == 9 && is_last_packet && timestamp == 10) {
        printf("test7-BIS passed\n");
    }
    else {
        printf("test7-BIS failed, result is %d\n", result);
    }


    // retrieve from position 0, should fail
    ptr_result = (char *) pbuf_retrieve(pbuf, 
        0,  /* test parameter*/
        &timestamp, &is_last_packet, 
        &offset, &video_width, &video_height,
        &data_length
        );
    if (ptr_result == NULL) {
        printf("test8 passed\n");
    }

    // trying to inset more data than the buffer can hold
    uint8_t long_test[]="1234567890ABCDEFGHIJ";
    // insert into position 1
    //                        num, ts, last,off,w, h, data, len
    result = pbuf_insert(pbuf, 1, 10, true, 7, 8, 9, long_test, strlen(long_test)+1);
    if (result == -1) {
        printf("test9 passed\n");
    }

    // trying to insert 0 bytes
    // insert into position 1
    //                        num, ts, last,off,w, h, data, len
    result = pbuf_insert(pbuf, 1, 10, true, 7, 8, 9, long_test, 0);
    if (result == -1) {
        printf("test10 passed\n");
    }

    // insert new data in position 0
    //                        num,ts, last, off, w, h,  data, len
    result = pbuf_insert(pbuf, 0, 20, false, 21, 22, 23, test3, strlen(test3)+1);
    ptr_result = (char *) pbuf_retrieve(pbuf, 
        0,  /* test parameter*/
        &timestamp, &is_last_packet, 
        &offset, &video_width, &video_height,
        &data_length
    );
    //                           num,ts, last,off,w, h, data, len
    // result = pbuf_insert(pbuf, 7, 10, true, 7, 8, 9, test2, 8);
    if (memcmp(ptr_result, test3, strlen(test3) +1) == 0 && 
    data_length == strlen(test3) +1  && offset == 21 && video_width == 22 && video_height == 23 && !is_last_packet && timestamp == 20) {
        printf("test11 passed\n");
    }
    else {
        printf("test11 failed\n");
    }
    


    pbuf_destroy(pbuf);
}