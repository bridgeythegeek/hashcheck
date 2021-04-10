#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <semaphore.h>

#define ALLOC 1000000
#define ITEMS_PER_THREAD 1000

enum HashType {MD5, SHA1};

struct WorkerArgs {
    char **haystack;
    size_t haystack_count;
    char **needles;
    size_t needles_count;
    FILE *match;
    FILE *nomatch;
};

void print_usage() {
    printf("hashcheck - check a list of hashes to see if they're in another list of hashes.\n");
    printf("usage: hashcheck needles.txt --md5|--sha1 [haystack.txt]\n");
    printf("haystack.txt defaults to either md5.txt or sha1.txt in the current directory.\n");
    printf("1000 haystack items per thread with a maximum of 3 threads.\n");
}

sem_t semWorkers;
static pthread_mutex_t mutOutput = PTHREAD_MUTEX_INITIALIZER;
static size_t matched_total = 0;
static size_t nomatch_total = 0;

void* worker(void *args) {
    struct WorkerArgs *wargs = (struct WorkerArgs*)args;
    size_t matched_this = 0;
    pthread_mutex_lock(&mutOutput);
    printf("Starting thread with batch size %ld.\n", wargs->haystack_count);
    pthread_mutex_unlock(&mutOutput);
    for (size_t i=0; i<wargs->haystack_count; i++) {
        int matched = 0;
        for (size_t j=0; j<wargs->needles_count; j++) {
            int match = strcmp(wargs->needles[j], wargs->haystack[i]);
            if (match == 0) {
                matched = 1;
                break;
            }
            if (match > 0) {
                break;
            }
        }
        pthread_mutex_lock(&mutOutput);
        if (matched) {
            matched_total += 1;
            matched_this += 1;
        } else {
            nomatch_total += 1;
        }
        fprintf(matched ? wargs->match : wargs->nomatch, "%s", wargs->haystack[i]);
        pthread_mutex_unlock(&mutOutput);
        free(wargs->haystack[i]);
    }
    free(wargs->haystack);
    free(wargs);
    pthread_mutex_lock(&mutOutput);
    printf("Thread finished, matched %ld.\n", matched_this);
    pthread_mutex_unlock(&mutOutput);
    sem_post(&semWorkers);
    //printf("thread end\n");
}

pthread_t dispatch(char **needles, size_t needle_count, char **haystack, size_t hay_count, FILE *match, FILE *nomatch) {
    //printf("dispatch start\n");
    pthread_t tWorker;
    struct WorkerArgs *wargs;
    wargs = malloc(sizeof(struct WorkerArgs));
    wargs->haystack = haystack;
    wargs->haystack_count = hay_count;
    wargs->needles = needles;
    wargs->needles_count = needle_count;
    wargs->match = match;
    wargs->nomatch = nomatch;
    if (pthread_create(&tWorker, NULL, worker, wargs) != 0) {
        fprintf(stderr, "[E] Error creating worker thread!\n");
        exit(1);
    }
    //printf("dispatch end\n");
    return tWorker;
}

int main(int argc, char *argv[]) {

    // Process Options
    if (argc < 3 || argc > 4) {
        print_usage();
        exit(EXIT_FAILURE);
    }

    enum HashType run_hash_type;
    if (strcmp(argv[2], "--md5") == 0) {
        run_hash_type = MD5;
    }
    else if (strcmp(argv[2], "--sha1") == 0) {
        run_hash_type = SHA1;
    }
    else {
        print_usage();
        exit(EXIT_FAILURE);
    }

    char *haystack_filename;
    if (argc == 4) {
        haystack_filename = argv[3];
    }
    else {
        haystack_filename = run_hash_type == MD5 ? "md5.txt" : "sha1.txt";
    }

    const int NEEDLE_LEN = run_hash_type == MD5 ? 33 : 41;

    // Read the needles
    FILE *fNeedles = fopen(argv[1], "r");
    if (fNeedles==NULL) {
        fprintf(stderr, "[E] Couldn't open needles file: %s\n", argv[1]);
        exit(1);
    }

    char **needles = NULL;

    FILE *out_match = fopen("match.txt", "w");
    if (out_match == NULL) {
        fprintf(stderr, "Couldn't open file to save matches: %s\n", "match.txt");
        exit(EXIT_FAILURE);
    }
    FILE *out_nomatch = fopen("nomatch.txt", "w");
    if (out_nomatch == NULL) {
        fprintf(stderr, "Couldn't open file to save non-matches: %s\n", "nomatch.txt");
        exit(EXIT_FAILURE);
    }
    
    char *line = NULL;
    size_t len = 0;
    ssize_t read;
    size_t needle_count = 0;
    size_t this_line = 0;
    size_t invalid_hash = 0;
    while ((read = getline(&line, &len, fNeedles)) != -1) {
        
        this_line++;
        if (!(read == NEEDLE_LEN && read-1 == strspn(line, "0123456789abcdef"))) {
            fprintf(stderr, "[W] Ignoring line %ld, invalid hash.\n", this_line);
            invalid_hash++;
            continue;
        }
        
        // Do we need to realloc?
        if (needle_count % ALLOC == 0) {
            char **temp = realloc(needles, (needle_count+ALLOC) * sizeof(char*));
            if (temp == NULL) {
                fprintf(stderr, "Failed to realloc needles array. Must abort!\n");
                free(line);
                fclose(fNeedles);
                exit(EXIT_FAILURE);
            }
            needles = temp;
        }
        
        needles[needle_count] = malloc(NEEDLE_LEN+1);
        if (needles[needle_count] == NULL) {
            fprintf(stderr, "[E] Couldn't allocated memory for needle!\n");
            exit(1);
        }
        strcpy(needles[needle_count], line);
        needle_count++;
    }
    // In POSIX, a line should end with a line break
    if (line[read-1] != '\n') {
        fprintf(stderr, "[W] Last line didn't end with a line break! Hash likely ignored.\n");
    }
    free(line);
    fclose(fNeedles);

    printf("[I] Read %ld needles.\n", needle_count);
    printf("[W] %ld lines were ignored because they didn't contain a valid hash.\n", invalid_hash);

    sem_init(&semWorkers, 0, 3);

    // Read the haystack
    FILE *f = fopen(haystack_filename, "r");
    if (f == NULL) {
        fprintf(stderr, "[E] Couldn't read haystack file: %s\n", haystack_filename);
        return 0;
    }

    char **hay;
    hay = malloc(ITEMS_PER_THREAD * sizeof(char*));
    if (hay == NULL) {
        fprintf(stderr, "[E] Couldn't allocate memory for haystack hash!\n");
        return 0;
    }
    for (int i=0; i<ITEMS_PER_THREAD; i++) {
        hay[i] = malloc(NEEDLE_LEN+1);
        if (hay[i] == NULL) {
            fprintf(stderr, "[E] Couldn't allocate memory for haystack hash!\n");
            return 0;
        }
    }
    size_t hay_count = 0;
    while((read = getline(&line, &len, f)) != -1) {
        strcpy(hay[hay_count], line);
        hay_count++;
        if (hay_count == ITEMS_PER_THREAD) {
            // Start worker thread
            sem_wait(&semWorkers);
            pthread_t new_pt = dispatch(needles, needle_count, hay, hay_count, out_match, out_nomatch);
            pthread_join(new_pt, NULL);
            hay_count = 0;
            hay = malloc(ITEMS_PER_THREAD * sizeof(char*));
            if (hay == NULL) {
                fprintf(stderr, "[E] Couldn't allocate memory for haystack hash!\n");
                return 0;
            }
            for (int i=0; i<ITEMS_PER_THREAD; i++) {
                hay[i] = malloc(NEEDLE_LEN+1);
                if (hay[i] == NULL) {
                    fprintf(stderr, "[E] Couldn't allocate memory for haystack hash!\n");
                    return 0;
                }
            }
        }
    }

    free(line);
    fclose(f);
    
    if (hay_count > 0) {
        // Start worker thread
        sem_wait(&semWorkers);
        pthread_t new_pt = dispatch(needles, needle_count, hay, hay_count, out_match, out_nomatch); 
        pthread_join(new_pt, NULL);
    }

    // Freedom!
    for (size_t i=0; i<needle_count; i++) {
        free(needles[i]);
    }
    free(needles);
    pthread_mutex_destroy(&mutOutput);

    printf("[I] matched %ld, not matched %ld, total %ld.\n", matched_total, nomatch_total, matched_total+nomatch_total);

    printf("[I] Done.\n");
    exit(EXIT_SUCCESS);
}

