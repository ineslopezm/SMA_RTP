/*
Reads locally a .vtx file and plays it in the terminal.

Implementation:
- has a signal_handler function, that is executed if Ctrol-C is pressed. This function prints some stats
- main loop: reads a frame header from the file; with this header, it knows how much to read, and the time to wait before the next frame. Then reads the data and waits the time.


COMPILE as:
gcc -Wshadow -Wpedantic -Wall -Wextra -Wstrict-overflow -fno-strict-aliasing -o vitextplayer vitextplayer.c
*/

#include <sys/ioctl.h>
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <stdbool.h>
#include <sys/time.h>
#include <inttypes.h>
#include <arpa/inet.h>
#include <getopt.h>
#include <signal.h>

#include "../lib/vtx_file.h"

void get_arguments(int argc, char *argv[], char *filename, bool *verbose, int *repeat)
{

#define HELP printf("vitextplayer [-h] [-v] [-r repeat] filename\n"    \
                    "[-v] for verbose\n"                               \
                    "[-r repeat] to repeat the video 'repeat' times\n" \
                    "filename   name of the .vtx file to play");

    // default values
    *filename = '\0';
    *verbose = false;
    *repeat = 1;

    int opt;
    while ((opt = getopt(argc, argv, "hvr:")) != -1)
    {
        switch (opt)
        {
        case 'h':
            HELP;
            break;
        case 'v':
            *verbose = true;
            break;
        case 'r':
            *repeat = (int)strtol(optarg, NULL, 10);
            if (*repeat < 1)
            {
                fprintf(stderr, "Repeat must be a positive number\n");
                exit(EXIT_FAILURE);
            }
            break;
        case '?':

        default:
            HELP;
            exit(EXIT_FAILURE);
        }
    }

    if (optind < argc)
    {
        if (strlen(argv[optind]) <= 255)
        {
            strcpy(filename, argv[optind]);
        }
        else
        {
            fprintf(stderr, "Filename too long, must be up to 255\n");
            exit(EXIT_FAILURE);
        }
    }

    if (strlen(filename) == 0)
    {
        fprintf(stderr, "No filename given\n");
        exit(EXIT_FAILURE);
    }
}

// declared global to allow its use in the signal handler

struct timeval start_time;
uint32_t packets_played = 0;
char *frame = NULL;

void signal_handler(int signum)
{
    (void)signum; // this is to remove warning of 'unused signum'. It is unused, but it must be defined as an argument in the signal_handler

    // print stats
    struct timeval end_time;
    gettimeofday(&end_time, NULL);
    float elapsed_time = (end_time.tv_sec - start_time.tv_sec) + (end_time.tv_usec - start_time.tv_usec) / 1000000.0;
    printf("\n\nElapsed time: %f seconds\n", elapsed_time);
    printf("Packets played: %d\n", packets_played);

    free(frame);
    exit(EXIT_SUCCESS);
}

int select(int n, fd_set *conjunto_lectura, fd_set *conjunto_escritura, fd_set *conjunto_excepciones, struct timeval *timeout){
    printf();
}

int main(int argc, char *argv[])
{

    char filename[255];
    bool verbose;
    int repeat;

    // Primero llama al metodo get_arguments para coger los argumentos de la linea de
    // comandos
    get_arguments(argc, argv, filename, &verbose, &repeat);

    FILE *fp;
    fp = fopen(filename, "r");
    if (fp == NULL)
    {
        printf("Error opening file %s", filename);
        exit(EXIT_FAILURE);
    }

    // NOTE: configure stdout in full buffered mode, so that it writes only when executing fflush(stdout) or when the buffer is full.
    // This reduces the number of write() syscalls, which is important for performance
    if (setvbuf(stdout, NULL, _IOFBF, 0) < 0)
    {
        perror("setvbuf");
        exit(EXIT_FAILURE);
    }

    // install signal handler for SIGINT, SIGTERM
    sigaction(SIGINT, &(struct sigaction){.sa_handler = signal_handler}, NULL);
    sigaction(SIGTERM, &(struct sigaction){.sa_handler = signal_handler}, NULL);

    file_vtx_frame_header_t frame_header;

    // clear screen
    printf("\033[2J");

    struct timeval repetition_start_time, target_time, sleep_time;
    gettimeofday(&start_time, NULL);    // reference time for video playback
    repetition_start_time = start_time; // repetition_start_time is used to compute the time to sleep in reference to the start of the current repetition
    uint32_t first_timestamp = 0;
    bool first_frame = true;

    float inter_frame_us; // interframe time in microseconds
    size_t current_frame_size = 0, frame_size;

    while (repeat > 0)
    {
        repeat--;
        fseek(fp, 0, SEEK_SET);
        while (fread(&frame_header, sizeof(file_vtx_frame_header_t), 1, fp) == 1)
        {

            // compute time to sleep
            if (first_frame)
            {
                // first_timestamp = frame_header.timestamp;
                first_frame = false;
                first_timestamp = frame_header.timestamp;

                // There is no relative time to which to compare the first frame
                inter_frame_us = 0;
            }
            else
            {
                uint32_t theoretical_from_start_us = (frame_header.timestamp - first_timestamp) / 90000.0 * 1000000.0;
                // convert to timeval
                struct timeval theoretical_from_start_tv;
                theoretical_from_start_tv.tv_sec = theoretical_from_start_us / 1000000;
                theoretical_from_start_tv.tv_usec = theoretical_from_start_us % 1000000;

                // add difference to start time
                timeradd(&repetition_start_time, &theoretical_from_start_tv, &target_time);

                // get current time
                struct timeval current_time;
                gettimeofday(&current_time, NULL);

                // calculate time to sleep in timeval
                timersub(&target_time, &current_time, &sleep_time);

                // calculate time to sleep
                inter_frame_us = sleep_time.tv_sec * 1000000 + sleep_time.tv_usec;
            }

            // ensure that terminal is big enough
            struct winsize terminal_size;
            ioctl(STDOUT_FILENO, TIOCGWINSZ, &terminal_size);

            // height + 1 because of the status line
            if (frame_header.width > terminal_size.ws_col || frame_header.height + 1 > terminal_size.ws_row)
            {
                printf("Terminal is too small to display the video\n");
                exit(EXIT_FAILURE);
            }

// Read frame
// Allocate memory to contain both (1) control code to place cursor in top left corner and (2) frame data
#define CURSOR_TOP_LEFT "\033[1;1H"
            frame_size = strlen(CURSOR_TOP_LEFT) + frame_header.length;
            // only allocate more bytes for frame if it grows
            if (frame_size > current_frame_size)
            {
                frame = realloc(frame, frame_size);
                current_frame_size = frame_size;
            }

            // write the control code at the beginning of the frame
            sprintf(frame, CURSOR_TOP_LEFT);
            // read the frame data AFTER the control code
            if (fread(frame + strlen(CURSOR_TOP_LEFT), frame_header.length, 1, fp) != 1)
            {
                printf("Error reading frame in file %s", filename);
                exit(EXIT_FAILURE);
            }

            // play frame
            write(STDOUT_FILENO, frame, frame_size);

            printf("frame length: %d, timestamp: %d, width: %d, height: %d, format: %d, inter_frame_time %f\n", frame_header.length, frame_header.timestamp, frame_header.width, frame_header.height, frame_header.format, inter_frame_us);
            fflush(stdout);

            packets_played++;

            if (inter_frame_us < 0)
            {
                // This frame is late according to the absolute time at which it should be played,
                // There are many reasons for this, for example, the Operating System doing some time-consuming operation... or the system been too slow.
                // Some virtual machines may take very long to process syscalls, and the time may impact the video playback.
                // Just show this frame as soon as possible
                inter_frame_us = 0;
            }
            // actual sleep action
            usleep(inter_frame_us);
        }

        // prepare a new round: add the last interframe time to the start time
        // as the first frame does not wait
        timeradd(&target_time, &sleep_time, &repetition_start_time);
        first_frame = true;
    }

    // go to stats, fake signal
    signal_handler(0);
}