#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <float.h>
#include <math.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include "http.h"
#include "hashtable.h"
#include "c_utils.h"

/*
 * Macro-constantes.
 */

/**
 * @see https://stackoverflow.com/questions/1701055
 */
#define FLOAT_MAX_STRLEN 3 + DBL_MANT_DIG - DBL_MIN_EXP

/**
 * Limites des longueurs "clé: valeurs" des entêtes de requêtes / réponses.
 */
#define KEY_MAX_STRLEN 64
#define VALUE_MAX_STRLEN 512

/**
 * Nombre maximum de header autorisé dans une requête / réponse.
 */
#define MAX_HEADER 256

/**
 * Chemin vers la table de correspondance mime -> extension. Utilisée par
 * get_mime_type.
 */
#define MIME_FILE "./mime.types"

/*
 * Macro-fonctions.
 */

/**
 * Si val vaut NULL alors *err est mis à err_val et va au label free.
 */
#define CHECK_NULL_AND_FILL_ERR(val, err_val)                                  \
  do { if ((val) == NULL) { *err = err_val; goto free; } } while (0)

/**
 * Remplit str avec la valeur de msg tant que la valeur k est inférieure à 
 * max_k. Vérifie invalid_cond après le remplissage. Si invalid_cond vaut 1, 
 * alors *err sera mis à err_val et le programme ira au label free.  
 * 
 * @param msg          Le message à lire.
 * @param str          La chaîne à remplir.
 * @param sep          Le séparateur de ce que l'on souhaite lire.
 * @param max_k        Le maximum d'itération à effectuer sur max_k.
 * @param invalid_cond La condition à vérifier en fin de parcours.
 * @param err_val      La valeur de *err si invalid_cond vaut 1.
 */
#define READ_MSG_DATA(msg, str, sep, max_k, invalid_cond, err_val)                           \
  do {                                                                         \
    k = 0;                                                                     \
    while (*msg != 0 && *msg != sep && k < max_k) {                            \
      str[k] = *msg;                                                           \
      ++msg;                                                                   \
      ++k;                                                                     \
    }                                                                          \
    str[k] = 0;                                                                \
    if ((invalid_cond)) {                                                      \
      *err = err_val;                                                          \
      goto free;                                                               \
    }                                                                          \
    ++msg;                                                                     \
  } while (0)

/**
 * Applique strncat(dest, src, left) et soustraie à left strlen(src). Si left 
 * est négatif alors le programme ira au label free.
 */
#define CAT_AND_CHECK_LEFT(dest, src)                                          \
  do {                                                                         \
    strncat(dest, src, left);                                                  \
    size_t len = strlen(src);                                                  \
    if (len > left) {                                                          \
      goto free;                                                               \
    }                                                                          \
    left -= len;                                                               \
  } while (0)

/*
 * Structures de données.
 */

/**
 * Type contenant les headers d'une requête où d'une réponse.
 */
typedef struct http_headers {
  hashtable *headers;
} http_headers;

/**
 * Structure utilisée par la fonction http_response_header_to_str permettant
 * d'écrire dans une chaîne tout en ne dépassant pas sa limite de capacité.
 */
typedef struct string_write {
  char *str;
  size_t max;
} string_write;

/*
 * Prototypes.
 */

/**
 * L'une des fonctions de pré-hachage consillée par Kernighan et Pike pour 
 * les chaines de caractères.
 * 
 * @param s La chaîne à hacher.
 * 
 * @return  Le hachage de s.
 */
static size_t str_hashfun(const char *s);

/**
 * Ecrit dans acc "key: val".
 */
static void http_response_header_to_str(string_write *acc, const char *key, 
    const char *val);

/**
 * Lit une ligne dans fd et la stock dans buff de taille maximum buff_size.
 * Renvoie 1 en cas de succès et 0 si la fin du fichier a été atteinte. Renvoie
 * -1 en cas d'erreur.
 * 
 * @param fd        Le descripteur de fichier.
 * @param buff      Un pointeur où stocker la ligne.
 * @param buff_size La taille maximale de buff.
 * 
 * @return          1 en cas de succès où 0 si la fin du fichier a été atteinte.
 *                  -1 en cas d'erreur.
 */
static int read_line(int fd, char *buff, size_t buff_size);

/*
 * Fonctions permettant de manipuler une requête
 */

http_request *str_to_http_request(const char *str, int *err) {
  // Initialisation des variables
  char *str_p = (char *) str;
  size_t k = 0;
  char *key = NULL;
  char *value = NULL;
  // Allocation de la requête
  http_request *req = malloc(sizeof(*req) + strlen(str) + 1);
  http_headers *headers = NULL;
  CHECK_NULL_AND_FILL_ERR(req, MEMORY_ERROR);
  memset(req, 0, sizeof(*req) + strlen(str) + 1);
  // Lecture de la méthode
  READ_MSG_DATA(str_p, req->method, ' ', MAX_METHOD_STRLEN, 
      k == MAX_METHOD_STRLEN || !is_method_valid(req->method), 
      METHOD_NOT_ALLOWED);
  // Lecture de l'URI
  READ_MSG_DATA(str_p, req->uri, ' ', MAX_URI_STRLEN, k == MAX_URI_STRLEN,
      REQUEST_URI_TOO_LONG);
  // Lecture de la version
  char version[FLOAT_MAX_STRLEN + 1];
  memset(version, 0, FLOAT_MAX_STRLEN + 1);
  READ_MSG_DATA(str_p, version, '\r', FLOAT_MAX_STRLEN, 
    sscanf(version, "HTTP/%lf", &req->version) != 1, BAD_REQUEST);
  ++str_p;
  // Lecture et ajout des headers dans la table de hachage
  headers = malloc(sizeof(*headers));
  CHECK_NULL_AND_FILL_ERR(headers, MEMORY_ERROR);
  headers->headers = hashtable_empty(
    (int (*)(const void *, const void *)) strcmp, 
    (size_t (*)(const void *)) str_hashfun
  );
  CHECK_NULL_AND_FILL_ERR(headers->headers, MEMORY_ERROR);
  size_t i = 0;
  while (i < MAX_HEADER) {
    k = 0;
    // Allocation de la clé et de la valeur
    key = malloc(KEY_MAX_STRLEN + 1);
    CHECK_NULL_AND_FILL_ERR(key, MEMORY_ERROR);
    memset(key, 0, KEY_MAX_STRLEN + 1);
    value = malloc(VALUE_MAX_STRLEN + 1);
    CHECK_NULL_AND_FILL_ERR(value, MEMORY_ERROR);
    // Lit la clé
    while (*str_p != ':' && *str_p != '\n' && *str_p != 0) {
      key[k] = *str_p;
      ++k;
      ++str_p;
    }
    if (strlen(key) == 1) {
      // Si l'on rencontre la ligne vide on sort de la boucle
      free(key);
      free(value);
      break;
    }
    // Vérifie que la requête soit bien valide
    if (str_p == 0) {
      *err = BAD_REQUEST;
      goto free;
    }
    if (*str_p != ':' || *(++str_p) != ' ') {
      *err = BAD_REQUEST;
      goto free;
    }
    ++str_p;
    // Lit la valeur
    k = 0;
    while (*str_p != '\n' && *str_p != 0) {
      value[k] = *str_p;
      ++k;
      ++str_p;
    }
    ++str_p;
    CHECK_NULL_AND_FILL_ERR(hashtable_add(headers->headers, key, value), 
      MEMORY_ERROR);
    key = NULL;
    value = NULL;
    ++i;
  }
  ++str_p;
  req->headers = headers;
  // Remplit le corps de la requête
  strncpy(req->body, str_p, strlen(str) + 1);

  goto exit;
free:
  SAFE_FREE(req);
  SAFE_FREE(headers);
  SAFE_FREE(key);
  SAFE_FREE(value);
  if (headers != NULL) {
    hashtable_dispose(&headers->headers);
  }
exit:
  return req;
}

int is_method_valid(const char *method) {
  return       
       strncmp(method, GET, MAX_METHOD_STRLEN)     == 0
    || strncmp(method, HEAD, MAX_METHOD_STRLEN)    == 0
    || strncmp(method, POST, MAX_METHOD_STRLEN)    == 0
    || strncmp(method, PUT, MAX_METHOD_STRLEN)     == 0
    || strncmp(method, DELETE, MAX_METHOD_STRLEN)  == 0
    || strncmp(method, LINK, MAX_METHOD_STRLEN) == 0
    || strncmp(method, UNLINK, MAX_METHOD_STRLEN)   == 0;
}

int http_req_get_header(http_request *req, const char *header_name, char *buff, 
  size_t buff_size) {
  if (req == NULL || header_name == NULL || buff == NULL) {
    return -1;
  }
  const char *val;
  if ((val = hashtable_search(req->headers->headers, header_name)) == NULL) {
    return 0;
  }
  strncpy(buff, val, buff_size);
  return 1;
}

int http_req_get_URI_base(http_request *req, char *buff, size_t buff_size) {
  if (req == NULL || buff == NULL) {
    return -1;
  }
  size_t k = 0;
  while (k < buff_size && req->uri[k] != '?' && req->uri[k] != 0) {
    buff[k] = req->uri[k];
    ++k;
  }
  buff[k] = 0;

  return k != buff_size;
}

void http_request_free(http_request **req) {
  hashtable_dispose(&(*req)->headers->headers);
  free((*req)->headers);
  free(*req);
  *req = NULL;
}

/*
 * Fonctions permettant de manipuler une réponse
 */

http_response *http_response_empty() {
  http_response *res = malloc(sizeof(*res));
  CHECK_NULL(res);
  res->headers = malloc(sizeof(http_headers));
  if (res->headers == NULL) {
    free(res);
    goto free;
  }
  res->headers->headers = hashtable_empty(
    (int (*)(const void *, const void *)) strcmp, 
    (size_t (*)(const void *)) str_hashfun
  );
  if (res->headers->headers == NULL) {
    free(res->headers);
    free(res);
    res = NULL;
    goto free;
  }
  res->body = NULL;

free:
  return res; 
}

int http_response_to_str(http_response *res, size_t body_size, char *buff, 
    size_t buff_size) {
  int r = 1;
  CHECK_NULL(res);
  CHECK_NULL(buff);
  size_t left = buff_size;
  char status_msg[21 + 1]; // Internal Server Error -> 21
  if (!status_code_to_status_msg(res->status, status_msg, 21)) {
    r = -1;
    goto free;
  }
  int writed = snprintf(buff, buff_size, "HTTP/%.1lf %d %s\r\n", res->version, 
      res->status, status_msg);
  if (buff_size < (size_t) writed) {
    r = 0;
    goto free;
  }
  left -= (size_t) writed;
  string_write str_w = {
    .str = buff,
    .max = left
  };
  hashtable_apply(res->headers->headers, &str_w, 
    (void (*)(void *, const void *, const void *)) http_response_header_to_str);
  if (buff == NULL) {
    r = 0;
    goto free;
  }
  left = str_w.max;
  // 3 pour "\r\n" body et le \0
  if (body_size + 3 > left) {
    r = 0;
  }
  CAT_AND_CHECK_LEFT(buff, "\r\n");
  size_t header_size = strlen(buff);
  memcpy(&buff[strlen(buff)], res->body, MIN(body_size, left));
  if (left > 0) {
    buff[header_size + body_size] = 0;
  } else {
    r = 0;
  }

free:
  return r;
}

int http_response_add_header(http_response *res, const char *name, 
    const char *value) {
  int r = -1;
  CHECK_NULL(res);
  CHECK_NULL(name);
  CHECK_NULL(value);
  // Copie du nom
  size_t name_len = strlen(name);
  char *name_cpy = malloc(name_len + 1);
  CHECK_NULL(name_cpy);
  memset(name_cpy, 0, name_len + 1);
  strcpy(name_cpy, name);
  // Copie de la valeur
  size_t value_len = strlen(value);
  char *value_cpy = malloc(value_len + 1);
  if (value_cpy == NULL) {
    free(name_cpy);
    goto free;
  }
  memset(value_cpy, 0, value_len + 1);
  strcpy(value_cpy, value);
  // Ajout du couple nom valeur dans la table de hachage
  const void *ptr = hashtable_add(res->headers->headers, name_cpy, value_cpy);
  if (ptr == NULL) {
    free(name_cpy);
    free(value_cpy);
    goto free;
  }

  r = 1;
free:
  return r;
}

void http_response_free(http_response **res) {
  hashtable_dispose(&(*res)->headers->headers);
  free((*res)->headers);
  free(*res);
  *res = NULL;
}

/*
 * Fonctions utiles.
 */

void http_err_to_string(FILE *out, int err) {
  switch (err) {
    case MEMORY_ERROR:
      fprintf(out, "Une erreur mémoire est survenue (Pas assez d'espace)\n");
      break;
    case BAD_REQUEST:
      fprintf(out, "La requête HTTP est mal formée\n");
      break;
    case METHOD_NOT_ALLOWED:
      fprintf(out, "La méthode de la requête est mal formée\n");
      break;
    case REQUEST_URI_TOO_LONG:
      fprintf(out, "L'URI de la requête est trop long\n");
      break;
    default:
      fprintf(out, "Erreur inconnue (Code : %d)", err);
      break;
  }
}

static size_t str_hashfun(const char *s) {
  size_t h = 0;
  for (const unsigned char *p = (const unsigned char *) s; *p != 0; ++p) {
    h = 37 * h + *p;
  }

  return h;
}

int get_mime_type(const char *filename, char *buff, size_t buff_size) {
  if (buff_size) {}
  // Initialisation des variables
  int r = -1;
  int mime_file = -1;
  long line_max = sysconf(_SC_LINE_MAX);
  char line[(line_max > 0 ? line_max : 0) + 1];
  CHECK_ERR_AND_FREE(line_max, -1);
  // Vérifie les paramètres
  CHECK_NULL(filename);
  CHECK_NULL(buff);
  // Extrait l'extension de filename
  char *extension = strrchr(filename, '.') + 1;
  CHECK_NULL(extension);
  // Ouvre le fichier contenant les MIME
  CHECK_ERR_AND_FREE(mime_file = open(MIME_FILE, O_RDONLY), -1);
  size_t k;
  int found = 0;
  // Lit le fichier ligne par ligne
  while (!found && read_line(mime_file, line, (size_t) line_max) > 0) {
    if (line[0] == '#') {
      continue;
    }
    k = 0;
    // Récupère le MIME de la ligne
    while (k < buff_size && line[k] != '\t') {
      buff[k] = line[k];
      ++k;
    }
    buff[k] = 0;
    // Lit l'extension associée
    while (line[k] == '\t') {
      ++k;
    }
    line[strlen(line) - 2] = 0;
    // Vérifie que l'extension soit bien celle demandée
    char *saveptr;
    char *token = strtok_r(line + k, " ", &saveptr);
    do {
      if (strcmp(token, extension) == 0) {
        found = 1;
      }
    } while ((token = strtok_r(NULL, " ", &saveptr)) != NULL);
  }
  if (!found) {
    r = 0;
    goto free;
  }

  r = 1;
free:
  if (mime_file > -1) {
    if (close(mime_file) < 0) r = -1;
  }
  return r;
}

int status_code_to_status_msg(int code, char *buff, size_t buff_size) {
  size_t len = 15;
  int status[] = {
    200, 201, 202, 204, 301, 302, 304, 400, 401, 403, 404, 500, 501, 502, 503
  };
  const char *messages[] = {
    "OK", "Created", "Accepted", "No Content", "Moved Permanently", 
    "Moved Temporarily", "Not Modified", "Bad Request", "Unauthorized", 
    "Forbidden", "Not Found", "Internal Server Error", "Not Implemented",
    "Bad Gateway", "Service Unavailable"
  };
  for (size_t i = 0; i < len; ++i) {
    if (status[i] == code) {
      strncpy(buff, messages[i], buff_size);
      return 1;
    }
  }

  return 0;
}

static void http_response_header_to_str(string_write *acc, const char *key, 
    const char *val) {
  // Si acc vaut NULL alors il y a eu débordement
  if (acc == NULL) {
    return;
  }
  size_t length = strlen(key) + + strlen(": ") + strlen(val) + 3;
  char header[length];
  int writed = snprintf(header, length, "%s: %s\r\n", key, val);
  if ((size_t) writed > length) {
    acc = NULL;
    return;
  }
  strncat(acc->str, header, acc->max);
  acc->max -= strlen(header);
}

static int read_line(int fd, char *buff, size_t buff_size) {
  ssize_t r = 1;
  size_t k = 0;
  while (k < buff_size && (r = read(fd, buff + k, 1)) > 0 && buff[k++] != '\n');
  if (k <= buff_size) {
    buff[k] = 0;
  }

  return r > 0 ? 1 : (int) r;
}
