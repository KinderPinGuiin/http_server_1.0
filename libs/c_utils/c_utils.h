/**
 * A set of macro-functions that make the code more readable.
 */

#ifndef C_UTILS
#define C_UTILS

#include <errno.h>
#include <time.h>

/*
 * ##################
 * # Error handling #
 * ##################
 */

#ifdef VERBOSE

/**
 * If val is less than 0 :
 * - "Error at line x" is printed with x the current line of your program. 
 * - If errno is greater than 0 then a perror is executed.
 * - Finally, it exit with the code EXIT_FAILURE.
 * 
 * @note Non thread safe (Use of perror).
 * @param val The value.
 */
#define CHECK_ERR_AND_EXIT(val)                                                \
  do {                                                                         \
    if ((val) < 0) {                                                           \
      fprintf(stderr, "Error at line %d", __LINE__);                           \
      if (errno > 0) {                                                         \
        perror(" ");                                                           \
      } else {                                                                 \
        fprintf(stderr, "\n");                                                 \
      }                                                                        \
      exit(EXIT_FAILURE);                                                      \
    }                                                                          \
  } while(0)

/**
 * If val is less than 0 :
 * - The variable r is set to r_val.
 * - "Error at line x" is printed with x the current line of your program. 
 * - If errno is greater than 0 then a perror is executed.
 * - goto the label free in your function.
 * 
 * @note Non thread safe (Use of perror).
 * @param val The value.
 * @param r_val The return value of the function.
 */
#define CHECK_ERR_AND_FREE(val, r_val)                                         \
  do {                                                                         \
    if ((val) < 0) {                                                           \
      r = r_val;                                                               \
      fprintf(stderr, "Error at line %d", __LINE__);                           \
      if (errno > 0) {                                                         \
        perror(" ");                                                           \
        errno = 0;                                                             \
      } else {                                                                 \
        fprintf(stderr, "\n");                                                 \
      }                                                                        \
      goto free;                                                               \
    }                                                                          \
  } while(0)

/**
 * If val is less than 0 :
 * - "Error at line x" is printed with x the current line of your program. 
 * - If errno is greater than 0 then a perror is executed.
 * - return with r_val
 * 
 * @note Non thread safe (Use of perror).
 * @param val The value.
 * @param r_val The return value of the function.
 */
#define CHECK_ERR_AND_RETURN(val, r_val)                                       \
  do {                                                                         \
    if ((val) < 0) {                                                           \
      fprintf(stderr, "Error at line %d", __LINE__);                           \
      if (errno > 0) {                                                         \
        perror(" ");                                                           \
        errno = 0;                                                             \
      } else {                                                                 \
        fprintf(stderr, "\n");                                                 \
      }                                                                        \
      return r_val;                                                            \
    }                                                                          \
  } while(0)

/**
 * If val is equals to NULL :
 * - goto the label free of your function
 * 
 * @note Thread safe.
 * @param val The variable / value to check.
 */
#define CHECK_NULL(val)                                                        \
  do {                                                                         \
    if ((val) == NULL) {                                                       \
      fprintf(stderr, "The value of %s is null\n", #val);                      \
      goto free;                                                               \
    }                                                                          \
  } while(0)

#else

/**
 * If val is less than 0 :
 * - Exit with the code EXIT_FAILURE.
 * 
 * @note Thread safe.
 * @param val The value.
 */
#define CHECK_ERR_AND_EXIT(val)                                                \
  do { if ((val) < 0) { exit(EXIT_FAILURE); } } while(0)

/**
 * If val is less than 0 :
 * - The variable r is set to r_val.
 * - goto the label free in your function.
 * 
 * @note Thread safe.
 * @param val The value.
 * @param r_val The return value of the function.
 */
#define CHECK_ERR_AND_FREE(val, r_val)                                         \
  do {                                                                         \
    if ((val) < 0) {                                                           \
      r = r_val;                                                               \
      goto free;                                                               \
    }                                                                          \
  } while(0)

/**
 * If val is less than 0 :
 * - return with r_val
 * 
 * @note Thread safe.
 * @param val The value.
 * @param r_val The return value of the function.
 */
#define CHECK_ERR_AND_RETURN(val, r_val)                                       \
  do {                                                                         \
    if ((val) < 0) {                                                           \
      return r_val;                                                            \
    }                                                                          \
  } while(0)

/**
 * If val is equals to NULL :
 * - goto the label free of your function
 * 
 * @note Thread safe.
 * @param val The variable / value to check.
 */
#define CHECK_NULL(val)                                                        \
  do {                                                                         \
    if ((val) == NULL) {                                                       \
      goto free;                                                               \
    }                                                                          \
  } while(0)

#endif

/*
 * #######################
 * # Number manipulation #
 * #######################
 */

/**
 * If x is less or equal than y it choose x, else it choose y.
 * 
 * @note Thread safe.
 * @param x
 * @param y 
 */
#define MIN(x, y) (((x) <= (y)) ? (x) : (y))

/**
 * If x is greater or equal than y it choose x, else it choose y.
 * 
 * @note Thread safe.
 * @param x
 * @param y 
 */
#define MAX(x, y) (((x) >= (y)) ? (x) : (y))

/**
 * Set var to a random integer between a and b. In case of error, if err is not
 * null, is value is set to -1 and var is equal to 0. If err is null, then var
 * is equal to 0. In both cases, errno is set properly.
 * 
 * @note Thread safe.
 * @param var The variable to initialize.
 * @param a The lower bound.
 * @param b The upper bound.
 * @param err The error variable. Can be set to null.
 */
#define RAND_INT(var, a, b, err)                                               \
  do {                                                                         \
    struct timespec ts;                                                        \
    if (clock_gettime(CLOCK_REALTIME, &ts) < 0) {                              \
      if (err != NULL) { *((int *) err) = -1; }                                \
      var = 0;                                                                 \
    } else {                                                                   \
      time_t t = (ts.tv_sec * 1000000) + ts.tv_nsec;                           \
      var = rand_r((unsigned int *) &t) % (b - a + 1) + a;                     \
    }                                                                          \
  } while(0)

/*
 * ###################
 * # Memory handling #
 * ###################
 */

/**
 * Allocates size bytes and stock the adress to the allocated memory into var.
 * If var is equals to NULL, then if goes to the label free of your function.
 * 
 * @note Thread safe.
 * @param var The variable where to store the adress of the allocated memory.
 * @param size The size of the allocated memory.
 */
#define SAFE_MALLOC(var, size)                                                 \
  do { var = malloc((size_t) (size)); CHECK_NULL(var); } while(0)

/**
 * Free var only if his value is not NULL.
 * 
 * @note Thread safe.
 * @param var The variable to free.
 */
#define SAFE_FREE(var)                                                         \
  do { if ((var) != NULL) { free((var)); var = NULL; } } while(0)

/*
 * ###################
 * # String handling #
 * ###################
 */

#define STRINGIFY(x) #x

/**
 * Convert a macro constant to string
 * 
 * @note Thread safe.
 * @param x The macro constant.
 */
#define TOSTRING(x) STRINGIFY(x)

#endif
