/**
 * Module permettant de manipuler des sockets TCP facilement.
 */

#ifndef _SOCKET_TCP
#define _SOCKET_TCP

#include <stdint.h>
#include <sys/types.h>

typedef struct socket_tcp socket_tcp;

/**
 * Rempli la structure pointée par psocket qui sera préalablement allouée.
 * Renvoie 0 en cas de succès et -1 sinon.
 * 
 * @param psocket La structure à remplir.
 * @return        0 en cas de succès et -1 sinon.
 */
int init_socket_tcp(socket_tcp *psocket);

/**
 * Renvoie la taille d'une structure socket_tcp. Utile pour malloc une structure
 * de ce type.
 */
size_t socket_tcp_get_size();

/**
 * Connecte la socket_tcp pointée par osocket sur la machine à l'adresse addr
 * et au port port. Renvoie -1 en cas d'erreur ou 0 sinon.
 * 
 * @param osocket La socket à connecter.
 * @param addr    L'adresse où se connecter.
 * @param port    Le port.
 * 
 * @return        0 en cas de succès et -1 sinon.
 */
int connect_socket(socket_tcp *osocket, const char *addr, uint16_t port);

/**
 * Fais écouter la socket_tcp pointée par osocket à l'adresse addr et au port 
 * port. Renvoie -1 en cas d'erreur ou 0 sinon.
 * 
 * @param isocket La socket à faire écouter.
 * @param addr    L'adresse où écouter.
 * @param port    Le port.
 * 
 * @return        0 en cas de succès et -1 sinon.
 */
int listen_socket(socket_tcp *isocket, const char *addr, uint16_t port);

/**
 * Met la socket_tcp pointée par s_listening en attente de connexion. Lors d'une
 * connexion la socket_tcp pointée par s_service sera remplie avec les 
 * informations du client. Renvoie 0 en cas de succès et -1 sinon.
 * 
 * @note              L'appel de cette fonction est bloquant jusqu'à la 
 *                    prochaine connexion.
 * 
 * @param s_listening La socket d'écoute.
 * @param s_service   La socket de service.
 * 
 * @return            0 en cas succès et -1 sinon.
 */
int accept_socket_tcp(socket_tcp *s_listening, socket_tcp *s_service);

/**
 * Ecrit length octets de buffer sur la socket_tcp pointée par nsocket. Renvoie
 * le nombre d'octets écrits en cas de succès et -1 en cas d'erreur.
 * 
 * @param osocket La socket sur laquelle écrire.
 * @param buffer  Le message à écrire.
 * @param length  La longueur maximum à écrire.
 * 
 * @return Le nombre d'octets écrits ou -1 en cas d'erreur.
 */
ssize_t write_socket_tcp(const socket_tcp *osocket, const void *buffer, 
    size_t length);

/**
 * Lit length octets  sur la socket_tcp pointée par nsocket et les stock dans 
 * buffer. Renvoie le nombre d'octets lus en cas de succès et -1 en cas 
 * d'erreur.
 * 
 * @param nsocket La socket sur laquelle lire.
 * @param buffer  Le buffer dans lequel stocker le message lu.
 * @param length  La longueur maximum à lire.
 * 
 * @return Le nombre d'octets lus ou -1 en cas d'erreur.
 */
ssize_t read_socket_tcp(const socket_tcp *nsocket, void *buffer, 
    size_t length);

/**
 * Ferme la socket associée à socket. Renvoie 0 en cas de succès et -1 sinon.
 * 
 * @param socket La socket_tcp à fermer.
 * 
 * @return       0 en cas de succès et -1 sinon.
 */
int close_socket_tcp(socket_tcp *socket);

#endif