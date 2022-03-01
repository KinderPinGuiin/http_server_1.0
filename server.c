#define VERBOSE

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

// Port HTTP
#define PORT 80

#define ERR EXIT_FAILURE

#define BACKLOG 100

// Temporaire
#define MAX_REQUEST_STRLEN 4096

// Dossier racine où se trouve les différents fichiers html/css/js
#define WEB_BASE "./www"

/*
 * Types de données
 */

typedef struct thread_arg {
  int sockfd;
} thread_arg;

/*
 * Prototypes
 */

/**
 * Fonctions permettants de gérer les signaux, en cas d'erreurs celles-ci 
 * quittent le programme.
 */
void handle_signals();
void sig_free();

/**
 * Fonction appelée par un thread lors d'une requête sur le serveur.
 * 
 * @param arg Un pointeur vers une structure de type thread_arg.
 */
void *send_response(void *arg);

int sockfd = -1;
adresse_internet *addr_in = NULL;

int main(void) {
  // Gestion des signaux
  handle_signals();
  // Création et mise en écoute de la socket serveur
  int r = EXIT_SUCCESS;
  struct sockaddr_in addr;
  memset(&addr, 0, sizeof(struct sockaddr_in));
  addr_in = adresse_internet_any(PORT);
  CHECK_NULL(addr_in);
  CHECK_ERR_AND_FREE(adresse_internet_to_sockaddr(addr_in, (struct sockaddr *) &addr), ERR);
  CHECK_ERR_AND_FREE(sockfd = socket(AF_INET, SOCK_STREAM, 0), ERR);
  int opt = 1;
  // Permet de ne pas s'occuper des sockets en TIME_WAIT
  CHECK_ERR_AND_FREE(
    setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR | 15, &opt, 
      sizeof(opt)),
    ERR
  );
  CHECK_ERR_AND_FREE(bind(sockfd, (struct sockaddr *) &addr, sizeof(struct sockaddr_in)), ERR);
  CHECK_ERR_AND_FREE(listen(sockfd, BACKLOG), ERR);

  int client = -1;
  while ((client = accept(sockfd, NULL, NULL))) {
    // Accepte les requêtes et créé un thread pour chaque socket de service
    pthread_t t;
    thread_arg *arg = malloc(sizeof(*arg));
    CHECK_NULL(arg);
    arg->sockfd = client;
    CHECK_ERR_AND_FREE(pthread_create(&t, NULL, send_response, arg), ERR);
    if (pthread_detach(t) != 0) {
      r = ERR;
      goto free;
    }
  }

free:
  if (sockfd != -1) {
    if (close(sockfd) < 0) {
      perror("Impossible de fermer la socket serveur ");
    }
  }
  if (r < 0) {
    http_err_to_string(stderr, r);
  }
  return r;
}

void handle_signals() {
  struct sigaction action;
  action.sa_handler = sig_free;
  action.sa_flags = 0;
  CHECK_ERR_AND_EXIT(sigfillset(&action.sa_mask));
  // On associe l'action à différents signaux
  CHECK_ERR_AND_EXIT(sigaction(SIGINT, &action, NULL));
  CHECK_ERR_AND_EXIT(sigaction(SIGQUIT, &action, NULL));
  CHECK_ERR_AND_EXIT(sigaction(SIGTERM, &action, NULL));
  CHECK_ERR_AND_EXIT(sigaction(SIGPIPE, &action, NULL));
}

void sig_free() {
  int r = EXIT_SUCCESS;
  fprintf(stdout, "\nInterruption du serveur suite à un signal\n");
  if (sockfd != -1) {
    if (close(sockfd) < 0) {
      r = EXIT_FAILURE;
      perror("Impossible de fermer la socket serveur");
    }
  }
  if (addr_in != NULL) {
    adresse_internet_free(addr_in);
  }

  exit(r);
}

void *send_response(void *arg) {
  int client = ((thread_arg *) arg)->sockfd;
  int r = EXIT_SUCCESS;
  http_request *req = NULL;
  http_response *res = NULL;
  char uri_base[MAX_URI_STRLEN + 1];
  char file_path[MAX_URI_STRLEN + strlen(WEB_BASE) + 2];
  char response[262144 + 1];
  memset(response, 0, 262144 + 1);

  char msg[MAX_REQUEST_STRLEN + 1];
  memset(msg, 0, MAX_REQUEST_STRLEN + 1);
  recv(client, msg, MAX_REQUEST_STRLEN, 0);
  // Au cas où le navigateur fasse une requête vide
  if (strlen(msg) == 0) {
    goto free;
  }
  fprintf(stderr, "Requête :\n%s", msg);

  // Récupère l'URI afin de créer le chemon vers le fichier demandé
  CHECK_NULL(req = str_to_http_request(msg, &r)); // TODO : Refaire str_to_http_request avec un body binaire
  http_req_get_URI_base(req, uri_base, MAX_URI_STRLEN);
  if (uri_base[strlen(uri_base) - 1] == '/') {
    strncpy(uri_base, "/index.html", MAX_URI_STRLEN);
  }
  sprintf(file_path, "%s%s", WEB_BASE, uri_base);

  // Lit le contenu du fichier
  int fd;
  off_t file_size = 0;
  if ((fd = open(file_path, O_RDONLY)) < 0) {
    if (errno == ENOENT) {
      snprintf(response, 262144, "HTTP/1.0 404 Not Found\r\n\r\n");
      send(client, response, MIN(strlen(response), 262144), 0);
      goto free;
    }
  }

  res = http_response_empty();
  CHECK_ERR_AND_FREE((int) (file_size = lseek(fd, 0, SEEK_END)), ERR);
  CHECK_ERR_AND_FREE((int) (lseek(fd, 0, SEEK_SET)), ERR);
  res->body = malloc((size_t) file_size);
  CHECK_NULL(res->body);
  CHECK_ERR_AND_FREE(read(fd, res->body, (size_t) file_size), ERR);

  res->version = 1.0;
  res->status = 200;
  char mime[1024 + 1];
  get_mime_type(file_path, mime, 1024);
  CHECK_ERR_AND_FREE(
    http_response_add_header(res, CONTENT_TYPE, mime), ERR
  );
  char file_size_str[256 + 1];
  sprintf(file_size_str, "%zu", (size_t) file_size);
  CHECK_ERR_AND_FREE(
    http_response_add_header(res, CONTENT_LENGTH, file_size_str), ERR
  );
  http_response_to_str(res, (size_t) file_size, response, 262144);
  send(client, response, strlen(response) - strlen((const char *) res->body) + (size_t) file_size, 0);

free:
  if (req != NULL) {
    http_request_free(&req);
  }
  if (res != NULL) {
    SAFE_FREE(res->body);
    http_response_free(&res);
  }
  close(client);
  free(arg);
  pthread_exit(&r);
}
