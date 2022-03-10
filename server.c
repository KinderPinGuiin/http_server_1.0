// TODO : Taille de réponse variable
// TODO : Vérifier les ../ dans l'URL
// TODO : Logs
// TODO : Config
// TODO : Changer l'image

#define VERBOSE
#define _POSIX_C_SOURCE 200809L

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <fcntl.h>
#include <pthread.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include "c_utils.h"
#include "adresse_internet.h"
#include "http.h"
#include "socket_tcp.h"

/*
 * Macro-constantes
 */

// Port HTTP
#define PORT 80

#define ERR EXIT_FAILURE

#define BACKLOG 100

// Temporaire
#define MAX_REQUEST_STRLEN 4096

// Dossier racine où se trouvent les différents fichiers
#define WEB_BASE "./www"

// Taille maximale d'une réponse, celle-ci est susceptible d'être modifiée si 
// dépassée via des realloc.
#define MAX_RESPONSE_SIZE 200000

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

socket_tcp *sock = NULL;
socket_tcp *service = NULL;
adresse_internet *addr_in = NULL;
mime_finder *finder = NULL;

int main(void) {
  // Gestion des signaux
  handle_signals();
  int r = EXIT_SUCCESS;
  // Chargement du convertisseur MIME
  CHECK_NULL(finder = mime_finder_load("./utils/mime.types", &r));
  // Création et mise en écoute de la socket serveur
  SAFE_MALLOC(sock, socket_tcp_get_size());
  CHECK_ERR_AND_FREE(init_socket_tcp(sock), ERR);
  SAFE_MALLOC(service, socket_tcp_get_size());
  CHECK_ERR_AND_FREE(listen_socket(sock, "127.0.0.1", PORT), ERR);
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

  exit(r);
}

void *send_response(void *arg) {
  socket_tcp *client = ((thread_arg *) arg)->socket;
  int r = EXIT_SUCCESS;

  // Initialisation des variables
  http_request *req = NULL;
  http_response *res = NULL;
  char file_path[MAX_URI_STRLEN + strlen(WEB_BASE) + 2];
  // Le "- 4" prend en compte le UL et les () de SIZE_MAX
  char file_size_str[strlen(TOSTRING(SIZE_MAX)) - 4 + 1];
  char *response = NULL;

  // Lecture de la requête
  char msg[MAX_REQUEST_STRLEN + 1];
  memset(msg, 0, MAX_REQUEST_STRLEN + 1);
  read_socket_tcp(client, msg, MAX_REQUEST_STRLEN);
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
  sprintf(file_path, "%s%s", WEB_BASE, uri_base);

  // Ouvre le fichier demandé et calcule sa taille
  int fd;
  if ((fd = open(file_path, O_RDONLY)) < 0) {
    // Si celui-ci n'existe pas on renvoie une erreur 404
    if (errno == ENOENT) {
      const char *res = "HTTP/1.0 404 Not Found\r\n\r\n";
      write_socket_tcp(client, res, MIN(strlen(res), MAX_RESPONSE_SIZE));
      goto free;
    }
  }
  off_t file_size;
  CHECK_ERR_AND_FREE((int) (file_size = lseek(fd, 0, SEEK_END)), ERR);
  CHECK_ERR_AND_FREE((int) (lseek(fd, 0, SEEK_SET)), ERR);

  // Créé la réponse et la remplit avec les données du fichier
  res = http_response_empty();
  CHECK_NULL(res);
  // Version et statut
  res->version = 1.0;
  res->status = 200;
  // Header : Content-Type
  CHECK_ERR_AND_FREE(
    http_response_add_header(
        res, CONTENT_TYPE, get_mime_type(finder, file_path)), ERR
  );
  // Header : Content-Length
  sprintf(file_size_str, "%zu", (size_t) file_size);
  CHECK_ERR_AND_FREE(
    http_response_add_header(res, CONTENT_LENGTH, file_size_str), ERR
  );
  // Corps de la réponse
  ssize_t readed;
  res->body = malloc((size_t) file_size);
  CHECK_NULL(res->body);
  CHECK_ERR_AND_FREE(readed = read(fd, res->body, (size_t) file_size), ERR);

  // Convertit la réponse en chaîne et l'envoie
  size_t response_strlen = http_response_strlen(res) + (size_t) file_size;
  response = malloc(response_strlen + 1);
  CHECK_NULL(response);
  memset(response, 0, response_strlen + 1);
  http_response_to_str(res, (size_t) file_size, response, response_strlen);
  write_socket_tcp(client, response, response_strlen);

free:
  if (req != NULL) {
    http_request_free(&req);
  }
  if (res != NULL) {
    SAFE_FREE(res->body);
    http_response_free(&res);
  }
  SAFE_FREE(response);
  close_socket_tcp(client);
  free(client);
  free(arg);
  pthread_exit(&r);
}
