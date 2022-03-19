// TODO : Select pour lire la requête

#define VERBOSE

#define _POSIX_C_SOURCE 200809L
#define _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <fcntl.h>
#include <pthread.h>
#include <limits.h>
#include <semaphore.h>
#include <time.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include "c_utils.h"
#include "adresse_internet.h"
#include "http.h"
#include "socket_tcp.h"
#include "yml_parser.h"

/*
 * Macro-constantes
 */

// Port HTTP
#define DEFAULT_PORT 80

#define DEFAULT_IP "127.0.0.1"

#define ERR EXIT_FAILURE

#define DEFAULT_BACKLOG 100

// Dossier racine où se trouvent les différents fichiers
#define DEFAULT_WEB_BASE "./www"

#define DEFAULT_404_FILE "./www/status/404.html"

#define DEFAULT_304_FILE "./www/status/304.html"

#define MAX_REQUEST_STRLEN 4096

#define MIME_FINDER_FILE "./utils/mime.types"

#define DATE_MAX_STRLEN 24

#define HTTP_DATE_MAX_STRLEN 29

/*
 * Types de données
 */

typedef struct thread_arg {
  socket_tcp *socket;
} thread_arg;

/*
 * Prototypes
 */

/**
 * Fonctions permettants de gérer les signaux, en cas d'erreurs celles-ci 
 * quittent le programme.
 */
void handle_signals();
void free_server(int signum);

/**
 * Fonction appelée par un thread lors d'une requête sur le serveur.
 * 
 * @param arg Un pointeur vers une structure de type thread_arg.
 */
void *send_response(void *arg);

/**
 * Ecrit dans fd la chaîne de format format avec les arguments à la suite.
 * Le message sera précédé par la date. Renvoie 1 en cas de succès et 0 sinon.
 * 
 * @param fd     Le descripteur où écrire.
 * @param format Le format.
 * @param ...    Les arguments de la chaîne format.
 * 
 * @return       1 en cas de succès, -1 sinon.
 */
int log_in_file(int fd, const char *format, ...);

/**
 * Envoi la réponse http res associée à la requête req. La réponse aura le 
 * statut status et le chemin du corps sera file_path.
 * 
 * @param client    La socket sur laquelle envoyer la réponse.
 * @param req       La requête.
 * @param res       La réponse.
 * @param status    Le statut de la réponse.
 * @param file_path Le chemin du corps de la réponse.
 * 
 * @return          1 en cas de succès et -1 sinon.
 */
int send_http_response(socket_tcp *client, http_request *req, http_response *res, 
    int status, const char *file_path);

int http_request_ends_with_2_crlf(const char *request);

// Sockets
socket_tcp *sock = NULL;
socket_tcp *service = NULL;
adresse_internet *addr_in = NULL;

// MIME finder
mime_finder *finder = NULL;

// Configuration
yml_parser *conf = NULL;

// Logs
sem_t log_sem;
int requests_log_fd = -1;

int main(void) {
  // Gestion des signaux
  handle_signals();
  int r = EXIT_SUCCESS;
  // Chargement du convertisseur MIME
  CHECK_NULL(finder = mime_finder_load(MIME_FINDER_FILE, &r));
  
  // Chargement de la configuration
  CHECK_NULL(conf = init_yml_parser("./conf/server.yml", NULL));
  CHECK_ERR_AND_FREE(exec_parser(conf), ERR);
  int port = DEFAULT_PORT;
  char ip[INET_ADDRSTRLEN + 1];
  int backlog = DEFAULT_BACKLOG;
  strncpy(ip, DEFAULT_IP, INET_ADDRSTRLEN + 1);
  CHECK_ERR_AND_FREE(get(conf, "port", &port), ERR);
  CHECK_ERR_AND_FREE(get(conf, "ip", &ip), ERR);
  CHECK_ERR_AND_FREE(get(conf, "backlog", &backlog), ERR);
  
  // Initialisation du semaphore de log et ouverture du fichier
  CHECK_ERR_AND_FREE(
    requests_log_fd = open("./logs/requests.log", O_CREAT | O_APPEND 
        | O_WRONLY, S_IWUSR | S_IRUSR), -1
  );
  CHECK_ERR_AND_FREE(sem_init(&log_sem, 1, 1), ERR);

  // Création et mise en écoute de la socket serveur
  SAFE_MALLOC(sock, socket_tcp_get_size());
  CHECK_ERR_AND_FREE(init_socket_tcp(sock), ERR);
  SAFE_MALLOC(service, socket_tcp_get_size());
  CHECK_ERR_AND_FREE(listen_socket(sock, ip, (uint16_t) port, backlog), ERR);
  while (accept_socket_tcp(sock, service) == 0) {
    // Accepte les requêtes et crée un thread pour chaque socket de service
    pthread_t t;
    thread_arg *arg = malloc(sizeof(*arg));
    CHECK_NULL(arg);
    arg->socket = malloc(socket_tcp_get_size());
    if (arg->socket == NULL) {
      free(arg);
      goto free;
    }
    memcpy(arg->socket, service, socket_tcp_get_size());
    CHECK_ERR_AND_FREE(pthread_create(&t, NULL, send_response, arg), ERR);
    if (pthread_detach(t) != 0) {
      r = ERR;
      goto free;
    }
  }

free:
  free_server(SIGINT);
}

void handle_signals() {
  struct sigaction action;
  action.sa_handler = free_server;
  action.sa_flags = 0;
  CHECK_ERR_AND_EXIT(sigfillset(&action.sa_mask));
  // On associe l'action à différents signaux
  CHECK_ERR_AND_EXIT(sigaction(SIGINT, &action, NULL));
  CHECK_ERR_AND_EXIT(sigaction(SIGQUIT, &action, NULL));
  CHECK_ERR_AND_EXIT(sigaction(SIGTERM, &action, NULL));
  CHECK_ERR_AND_EXIT(sigaction(SIGPIPE, &action, NULL));
}

void free_server(int signum) {
  int r = EXIT_SUCCESS;
  if (signum == SIGPIPE) {
    fprintf(stderr, "Une erreur de transmission est survenue\n");
    exit(EXIT_FAILURE);
  }
  fprintf(stdout, "\nInterruption du serveur suite à un signal\n");
  if (sock != NULL) {
    if (close_socket_tcp(sock) < 0) {
      r = ERR;
      perror("Impossible de fermer la socket d'écoute ");
    }
    free(sock);
  }
  SAFE_FREE(service);
  if (addr_in != NULL) {
    adresse_internet_free(addr_in);
  }
  if (finder != NULL) {
    mime_finder_dispose(&finder);
  }
  if (conf != NULL) {
		if (free_parser(conf) < 0) {
			perror("Erreur lors de la libération du parseur yml ");
			r = EXIT_FAILURE;
		}
	}
  if (requests_log_fd > 0) {
    close(requests_log_fd);
  }

  exit(r);
}

void *send_response(void *arg) {
  socket_tcp *client = ((thread_arg *) arg)->socket;
  int r = ERR;

	// Chargement de la configuration
	char web_base[PATH_MAX + 1];
	strncpy(web_base, DEFAULT_WEB_BASE, PATH_MAX);
	get(conf, "www", web_base);

  // Initialisation des variables
  http_request *req = NULL;
  http_response *res = NULL;
  char file_path[MAX_URI_STRLEN + strlen(web_base) + 2];

  // Lecture de la requête
  char msg[MAX_REQUEST_STRLEN + 1];
  memset(msg, 0, MAX_REQUEST_STRLEN + 1);
  ssize_t read_r = read_socket_tcp_timeout(client, msg, MAX_REQUEST_STRLEN, 10, 
      (int (*)(const void *)) http_request_ends_with_2_crlf);
  if (read_r == 0) {
    fprintf(stderr, "Timeout\n");
    goto free;
  }
  // Au cas où le navigateur fasse une requête vide
  if (strlen(msg) == 0) {
    goto free;
  }
  // Transforme la chaîne en une structure http_request
  CHECK_NULL(req = str_to_http_request(msg, &r));

  // Récupère l'URI afin de créer le chemin vers le fichier demandé
  char uri_base[MAX_URI_STRLEN + 1];
  http_req_get_URI_base(req, uri_base, MAX_URI_STRLEN);
  // Si l'URI vaut / alors on ajoute index.html automatiquement
  if (uri_base[strlen(uri_base) - 1] == '/') {
    strncpy(uri_base, "/index.html", MAX_URI_STRLEN);
  }
  // Concatène le chemin demandé avec WEB_BASE afin récupérer le chemin final du
  // fichier demandé
  sprintf(file_path, "%s%s", web_base, uri_base);

  // Logs
  CHECK_ERR_AND_FREE(
    log_in_file(requests_log_fd, "A client requested %s\n", uri_base), ERR
  );

  // Créé la réponse et la remplit avec les données du fichier
  res = http_response_empty();
  CHECK_NULL(res);
  // Envoi la réponse
  CHECK_ERR_AND_FREE(send_http_response(client, req, res, 200, file_path), ERR);

  r = EXIT_SUCCESS;
free:
  if (req != NULL) {
    http_request_free(&req);
  }
  if (res != NULL) {
    http_response_free(&res);
  }
  close_socket_tcp(client);
  free(client);
  free(arg);
  pthread_exit(&r);
}

int log_in_file(int fd, const char *format, ...) {
  int r = 1;
  va_list args;
  va_start(args, format);

  CHECK_ERR_AND_FREE(sem_wait(&log_sem), -1);

  // Log la date
  struct tm t;
  time_t timestamp;
  CHECK_ERR_AND_FREE(time(&timestamp), -1);
  CHECK_NULL(localtime_r(&timestamp, &t));
  char date[DATE_MAX_STRLEN + 1];
  CHECK_NULL(asctime_r(&t, date));
  date[strlen(date) - 1] = 0;
  dprintf(fd, "[%s]: ", date);
  // Log le message
  vdprintf(fd, format, args);

  CHECK_ERR_AND_FREE(sem_post(&log_sem), -1);

free:
  va_end(args);
  return r;
}

int send_http_response(socket_tcp *client, http_request *req, http_response *res, 
    int status, const char *file_path) {
  int r = -1;
  // Le "- 4" prend en compte le UL et les () de SIZE_MAX
  char file_size_str[strlen(TOSTRING(SIZE_MAX)) - 4 + 1];
  char if_modified_date[HTTP_DATE_MAX_STRLEN + 1];
  memset(if_modified_date, 0, HTTP_DATE_MAX_STRLEN + 1);
  char *response = NULL;

  // Ouvre le fichier demandé et calcule sa taille
  int fd = -1;
  if (strstr(file_path, "../") != NULL || (fd = open(file_path, O_RDONLY)) < 0) {
    // Si celui-ci n'existe pas on renvoie une erreur 404
    send_http_response(client, req, res, 404, DEFAULT_404_FILE);
    r = 1;
    goto free;
  }

  // Gestion du If-Modified-Since
  struct stat stats;
  CHECK_ERR_AND_FREE(stat(file_path, &stats), -1);
  if (strcmp(DEFAULT_304_FILE, file_path) != 0 
      && http_req_get_header(req, IF_MODIFIED_SINCE, if_modified_date, 
          HTTP_DATE_MAX_STRLEN) > 0) {
    // Récupère la date de modification du fichier
    time_t file_timestamp = stats.st_mtim.tv_sec;
    // Récupère la date http et la converti en time_t
    struct tm if_modified_since_tm;
    memset(&if_modified_since_tm, 0, sizeof(struct tm));
    CHECK_NULL(strptime(if_modified_date, "%a, %d %b %Y %H:%M:%S GMT", 
                  &if_modified_since_tm));
    time_t if_modified_timestamp;
    CHECK_ERR_AND_FREE(if_modified_timestamp = mktime(&if_modified_since_tm), 
      -1);
    // Comparaison et envoi d'un code 304 si besoin
    if (file_timestamp < if_modified_timestamp) {
      send_http_response(client, req, res, 304, DEFAULT_304_FILE);
      r = 1;
      goto free;
    }
  }

  // Version et statut
  res->version = 1.0;
  res->status = status;
  // Header : Content-Type
  CHECK_ERR_AND_FREE(
    http_response_add_header(
        res, CONTENT_TYPE, get_mime_type(finder, file_path)), -1
  );
  // Header : Content-Length
  sprintf(file_size_str, "%zu", (size_t) stats.st_size);
  CHECK_ERR_AND_FREE(
    http_response_add_header(res, CONTENT_LENGTH, file_size_str), -1
  );
  // Corps de la réponse
  ssize_t readed;
  res->body = malloc((size_t) stats.st_size);
  CHECK_NULL(res->body);
  CHECK_ERR_AND_FREE(readed = read(fd, res->body, (size_t) stats.st_size), -1);

  // Convertit la réponse en chaîne et l'envoie
  size_t response_strlen = http_response_strlen(res) + (size_t) stats.st_size;
  response = malloc(response_strlen + 1);
  CHECK_NULL(response);
  memset(response, 0, response_strlen + 1);
  http_response_to_str(res, (size_t) stats.st_size, response, response_strlen);
  write_socket_tcp(client, response, response_strlen);

  r = 1;
free:
  if (fd > 0) {
    close(fd);
  }
  SAFE_FREE(res->body);
  SAFE_FREE(response);
  return r;
}

int http_request_ends_with_2_crlf(const char *request) {
  return strcmp(&request[strlen(request) - 4], "\r\n\r\n") == 0 ? 1 : 0;
}