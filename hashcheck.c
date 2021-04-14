#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <semaphore.h>

#define THREADS 3
#define ALLOC 1000000
#define ITEMS_PER_THREAD 1000000

enum HashType {MD5, SHA1};

struct WorkerArgs {
    size_t id;
    char **haystack;
    size_t haystack_count;
    char **needles;
    size_t needles_count;
    FILE *match;
};

void print_usage() {
    printf("hashcheck - check a list of hashes to see if they're in another list of hashes.\n");
    printf("usage: hashcheck needles.txt --md5|--sha1 [haystack.txt]\n");
    printf("haystack.txt defaults to either md5.txt or sha1.txt in the current directory.\n");
    printf("%d haystack items per thread with a maximum of %d threads.\n", ITEMS_PER_THREAD, THREADS);
}

int contains_lower(const char *text) {
    for (int i=0; i<strlen(text); i++) {
        if ('a' <= text[i] && text[i] <= 'z') {
            return 1;
        }
    }
    return 0;
}

int contains_upper(const char *text) {
    for (int i=0; i<strlen(text); i++) {
        if ('A' <= text[i] && text[i] <= 'Z') {
            return 1;
        }
    }
    return 0;
}

sem_t semWorkers;
static pthread_mutex_t mutOutput = PTHREAD_MUTEX_INITIALIZER;
static size_t thread_i = 0;
static size_t total_matched = 0;

void* worker(void *args) {
    struct WorkerArgs *wargs = (struct WorkerArgs*)args;
    for (size_t i=0; i<wargs->haystack_count; i++) {
        int matched = 0;
        size_t j;
        for (j=0; j<wargs->needles_count; j++) {
            int match = strcmp(wargs->needles[j], wargs->haystack[i]);
            if (match == 0) {
                matched = 1;
                break;
            }
            if (match > 0) {
                break;
            }
        }
        if (matched) {
            pthread_mutex_lock(&mutOutput);
            fprintf(wargs->match, "%s\n", wargs->haystack[i]);
            wargs->needles[j][0] = '\0'; // Nuke the needle because we've matched it and logged it.
            total_matched++;
            pthread_mutex_unlock(&mutOutput);
        }
        if (total_matched == wargs->needles_count) {
            break;
        }
        free(wargs->haystack[i]);
    }
    free(wargs->haystack);
    free(wargs);
    sem_post(&semWorkers);
}

pthread_t dispatch(char **needles, size_t needle_count, char **haystack, size_t hay_count, FILE *match) {
    pthread_t tWorker;
    struct WorkerArgs *wargs;
    wargs = malloc(sizeof(struct WorkerArgs));
    wargs->haystack = haystack;
    wargs->haystack_count = hay_count;
    wargs->needles = needles;
    wargs->needles_count = needle_count;
    wargs->match = match;
    wargs->id = thread_i;
    if (pthread_create(&tWorker, NULL, worker, wargs) != 0) {
        fprintf(stderr, "[E] Error creating worker thread!\n");
        exit(1);
    }
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

    const int NEEDLE_LEN = run_hash_type == MD5 ? 32 : 40;

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
        // for (int i=0; i<read; i++) { printf("%x.", line[i]); } printf("\n");
	
        if (strspn(line, "0123456789abcdefABCDEF\r\n") != read) {
            fprintf(stderr, "[W] Ignoring line %ld, invalid characters in line: %s", this_line, line);
            invalid_hash++;
            continue;
        }
        size_t valid_char_count = strspn(line, "0123456789abcdefABCDEF");
	    if (NEEDLE_LEN != valid_char_count) {
            fprintf(stderr, "[W] Ignoring line %ld, invalid hash: (%ld) %s", this_line, valid_char_count, line);
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
        
        needles[needle_count] = malloc(NEEDLE_LEN+1); // +\0
        if (needles[needle_count] == NULL) {
            fprintf(stderr, "[E] Couldn't allocated memory for needle!\n");
            exit(EXIT_FAILURE);
        }
        strcpy(needles[needle_count], line);
        needles[needle_count][NEEDLE_LEN] = '\0';
        needle_count++;
    }
    
    free(line);
    fclose(fNeedles);

    printf("[I] Read %ld needles.\n", needle_count);
    if (invalid_hash > 0) {
        printf("[W] %ld lines were ignored because they didn't contain a valid hash.\n", invalid_hash);
    }

    if (needle_count < 1) {
        printf("[I] Nothing to do!\n");
        fclose(out_match);
        fclose(out_nomatch);
	    exit(EXIT_SUCCESS);
    }

    sem_init(&semWorkers, 0, THREADS);

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
    size_t invalid_hay = 0;
    int reported_case = 0;
    int need_lf = 0;
    pthread_t *threads = NULL;
    size_t thread_i = 0;
    while((read = getline(&line, &len, f)) != -1) {
        if (!reported_case) {
            // Be nice, check the cases
            int needle_upper = contains_upper(needles[0]);
            int needle_lower = contains_lower(needles[0]);
            int hay_upper = contains_upper(line);
            int hay_lower = contains_lower(line);
            if (needle_upper !=0 && needle_lower != 0) {
                printf("[W] The first needle seems to contain both upper AND lower case characters?!\n");
            }
            if (needle_upper !=0 && hay_lower !=0) {
                printf("[W] The first needle seems to contain upper case characters, but the first hay item contains lower case characters?!\n");
            }
            if (needle_lower !=0 && hay_upper !=0) {
                printf("[W] The first needle seems to contain lower case characters, but the first hay item contains upper case characters?!\n");
            }
            reported_case = 1;
        }
        
        if (strspn(line, "0123456789abcdefABCDEF\r\n") != read) {
            fprintf(stderr, "[W] Ignoring line %ld, invalid characters in line: %s", this_line, line);
            invalid_hay++;
            continue;
        }
        size_t valid_char_count = strspn(line, "0123456789abcdefABCDEF");
	    if (NEEDLE_LEN != valid_char_count) {
            fprintf(stderr, "[W] Ignoring line %ld, invalid hay: (%ld) %s", this_line, valid_char_count, line);
            invalid_hay++;
            continue;
        }
        line[NEEDLE_LEN] = '\0';

        if (strcmp(line, needles[needle_count-1]) > 0) {
            printf("\n");
            printf("[I] Haystack is now beyond last needle, stopping reading the haystack.\n");
            printf("[I] Last needle: %s\n", needles[needle_count-1]);
            printf("[I] Just read  : %s", line);
            break;
        }
        
        strcpy(hay[hay_count], line);
        hay_count++;

        if (hay_count == ITEMS_PER_THREAD) {
            // Start worker thread
            need_lf = 1;
	        sem_wait(&semWorkers);
            
            // Do we need to realloc for thread pointers?
            if (thread_i % 1000 == 0) {
                pthread_t *temp = realloc(threads, (thread_i+1000) * sizeof(pthread_t));
                if (temp == NULL) {
                    fprintf(stderr, "Failed to realloc pthread array. Must abort!\n");
                    free(line);
                    fclose(f);
                    exit(EXIT_FAILURE);
                }
                threads = temp;
            }

            threads[thread_i] = dispatch(needles, needle_count, hay, hay_count, out_match);
            thread_i++;            

            pthread_mutex_lock(&mutOutput);
            fprintf(stderr, "\r[I] Items from haystack processed: %ld...", thread_i*ITEMS_PER_THREAD);
            pthread_mutex_unlock(&mutOutput);
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
    if (need_lf) {
        printf("\n");
    }

    free(line);
    fclose(f);
    
    if (hay_count > 0) {
        // Start worker thread
        sem_wait(&semWorkers);

        // Do we need to realloc for thread pointers?
        if (thread_i % 1000 == 0) {
            pthread_t *temp = realloc(threads, (thread_i+1000) * sizeof(pthread_t));
            if (temp == NULL) {
                fprintf(stderr, "Failed to realloc pthread array. Must abort!\n");
                free(line);
                fclose(f);
                exit(EXIT_FAILURE);
            }
            threads = temp;
        }

        threads[thread_i] = dispatch(needles, needle_count, hay, hay_count, out_match);
        thread_i++;
    }

    // Join with remaining threads
    printf("[I] Waiting for final threads...\n");
    for (size_t i=0; i<thread_i; i++) {
        pthread_join(threads[i], NULL);
    }
    printf("[I] Threads finished.\n");

    // What didn't match?
    for (size_t i=0; i<needle_count; i++) {
        // The length will be zero if it matched
        // so only unmatched left in needles
        if (strlen(needles[i]) == NEEDLE_LEN) {
            fprintf(out_nomatch, "%s\n", needles[i]);
        }
        free(needles[i]);
    }
    free(needles);
    fclose(out_match);
    fclose(out_nomatch);
    pthread_mutex_destroy(&mutOutput);

    printf("[I] matched %ld, not matched %ld, total %ld.\n", total_matched, needle_count-total_matched, needle_count);

    printf("[I] Done.\n");
    exit(EXIT_SUCCESS);
}
