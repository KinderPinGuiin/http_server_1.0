/**
 * Module permettant de manipuler des requêtes / réponses HTTP.
 * 
 * @see https://datatracker.ietf.org/doc/html/rfc1945
 */

#ifndef _HTTP
#define _HTTP

/*
 * Codes d'erreur de la librairie
 */

#define MEMORY_ERROR -1
#define BAD_REQUEST -2
#define METHOD_NOT_ALLOWED -3
#define REQUEST_URI_TOO_LONG -4

/**
 * Macros des méthodes de requête.
 *
 * @see https://datatracker.ietf.org/doc/html/rfc1945#page-30
 * @see https://datatracker.ietf.org/doc/html/rfc1945#page-58
 */

#define GET "GET"
#define HEAD "HEAD"
#define POST "POST"
#define PUT "PUT"
#define DELETE "DELETE"
#define LINK_METHOD "LINK"
#define UNLINK "UNLINK"

/**
 * Macros des en-têtes d'entités.
 * 
 * @see https://datatracker.ietf.org/doc/html/rfc1945#page-37
 */

#define ALLOW "Allow"
#define AUTHORIZATION "Authorization"
#define CONTENT_ENCODING "Content-Encoding"
#define CONTENT_LENGTH "Content-Length"
#define CONTENT_TYPE "Content-Type"
#define DATE "Date"
#define EXPIRES "Expires"
#define FROM "From"
#define IF_MODIFIED_SINCE "If-Modified-Since"
#define LAST_MODIFIED "Last-Modified"
#define LOCATION "Location"
#define PRAGMA "Pragma"
#define REFERER "Referer"
#define SERVER "Server"
#define USER_AGENT "User-Agent"
#define WWW_AUTHENTICATE "WWW-Authenticate"

/**
 * Macros des en-têtes additionnels.
 * 
 * @see https://datatracker.ietf.org/doc/html/rfc1945#page-58
 */

#define ACCEPT "Accept"
#define ACCEPT_CHARSET "Accept-Charset"
#define ACCEPT_ENCODING "Accept-Encoding"
#define ACCEPT_LANGUAGE "Accept-Language"
#define CONTENT_LANGUAGE "Content-Language"
#define LINK "Link"
#define MIME_VERSION "MIME-Version"
#define RETRY_AFTER "Retry-After"
#define TITLE "Title"
#define URI "URI"

/**
 * Macros utiles
 * 
 * @see https://datatracker.ietf.org/doc/html/rfc4288#page-6
 */

#define MIME_MAX_STRLEN 255

/**
 * Nombre maximum de header autorisé dans une requête / réponse.
 */
#define MAX_HEADER 256

/*
 * Structures de données
 */

typedef struct http_headers http_headers;

/**
 * Structure d'une requête HTTP.
 * 
 * @see https://datatracker.ietf.org/doc/html/rfc1945#page-23
 */
typedef struct http_request {
  // Ligne de commande
#define MAX_METHOD_STRLEN 7 // OPTIONS
  char method[MAX_METHOD_STRLEN + 1];
#define MAX_URI_STRLEN 512
  char uri[MAX_URI_STRLEN + 1];
  double version;
  http_headers *headers;
  char body[];
} http_request;

/**
 * Structure d'une réponse HTTP.
 * 
 * @see https://datatracker.ietf.org/doc/html/rfc1945#page-24
 */
typedef struct http_response {
  double version;
  int status;
  http_headers *headers;
  void *body;
} http_response;

/**
 * Structure permettant de convertir une extension en MIME.
 */

typedef struct mime_finder mime_finder;

/*
 * Fonctions permettant de manipuler une requête.
 */

/**
 * Convertit la chaîne str en structure http_request qui sera allouée 
 * dynamiquement et renvoie un pointeur vers celle-ci. Si err est différent de 
 * NULL, celui-ci contiendra 0 si tout se passe bien, sinon il contiendra un
 * code d'erreur négatif et la fonction renverra NULL.
 * 
 * @note      Le code d'erreur peut-être converti en chaîne grâce à la fonction
 *            http_err_to_string.
 * 
 * @param str La chaîne à convertir.
 * @param err Un pointeur d'erreur (Peut être NULL).
 * 
 * @return    Un pointeur vers une structure http_request en cas de succès.
 *            NULL sinon.
 */
http_request *str_to_http_request(const char *str, int *err);

/**
 * Renvoie 1 si la méthode method est valide et 0 sinon.
 * 
 * @param method La méthode à vérfier.
 * 
 * @return       1 si la méthode est valide et 0 sinon.
 */
int is_method_valid(const char *method);

/**
 * Récupère l'header de nom header_name dans req et stock sa valeur dans buff 
 * qui sera de taille buff_size. Renvoie 1 en cas de succès ou 0 si le header 
 * n'existe pas. Renvoie -1 si req, header_name ou buff vaut NULL.
 * 
 * @param req         La requête.
 * @param header_name Le nom du header que l'on souhaite extraire.
 * @param buff        Le buffer à remplir avec la valeur du header.
 * @param buff_size   La taille maximale de buff.
 * 
 * @return            1 en cas de succès et 0 si le header n'existe pas. -1 si
 *                    l'un des pointeurs est NULL.
 */
int http_req_get_header(http_request *req, const char *header_name, char *buff, 
  size_t buff_size);

/**
 * Extrait de la requête req la base de req->uri et la stock dans buff de 
 * taille maximale buff_size. Renvoie 1 en cas de succès et -1 si req ou buff 
 * vaut NULL. Renvoie 0 si la base a été tronquée.
 * 
 * @example         Si req->uri vaut /contact.html?q=152 alors buff vaudra 
 *                  /contact.html
 * 
 * @param req       La requête.
 * @param buff      Le buffer où stocker la base de l'URI.
 * @param buff_size La taille maximale de buff.
 * 
 * @return          1 en cas de succès et -1 si req ou buff vaut NULL. 0 si la 
 *                  base a été tronquée.
 */
int http_req_get_URI_base(http_request *req, char *buff, size_t buff_size);

/**
 * Libère les ressources associées à req.
 * 
 * @param req La requête à libérer.
 */
void http_request_free(http_request **req);

/*
 * Fonctions permettant de manipuler une réponse.
 */

/**
 * Alloue une structure http_response et renvoie son adresse ou NULL en cas 
 * d'erreur mémoire.
 * 
 * @return            L'adresse vers la structure allouée où NULL en cas 
 *                    d'erreur mémoire.
 */
http_response *http_response_empty();

/**
 * Convertit une http_response en chaîne de caractère et la stocke dans buff de
 * taille maximale buff_size. Renvoie 1 en cas de succès, -1 en cas d'erreur et 
 * 0 si la réponse a été tronquée.
 * 
 * @param res       L'adresse de la réponse à convertir.
 * @param body_size La taille du corps de la réponse
 * @param buff      La chaîne à remplir.
 * @param buff_size La taille de buff.
 * 
 * @return          1 en cas de succès, -1 en cas d'erreur. 0 si la réponse a  
 *                  été tronquée.
 */
int http_response_to_str(http_response *res, size_t body_size, char *buff, 
    size_t buff_size);

/**
 * Ajoute l'header de nom name et de valeur value dans res. Renvoie 1 en cas de
 * succès et -1 en cas d'erreur.
 * 
 * @param res   La réponse on l'on souhaite ajouter l'header.
 * @param name  Le nom de l'en-tête.
 * @param value La valeur de l'en-tête.
 * 
 * @return      1 en cas de succès et -1 sinon.
 */
int http_response_add_header(http_response *res, const char *name, 
    const char *value);

/**
 * Renvoie la taille de la chaîne représentant res sans compter res->body.
 * 
 * @param res La réponse dont on souhaite connaître la taille.
 * 
 * @return    La taille de la chaîne représentant la réponse.
 */
size_t http_response_strlen(http_response *res);

/**
 * Libère les ressources associées à res.
 * 
 * @param res La réponse à libérer.
 */
void http_response_free(http_response **res);

/*
 * Fonctions utiles.
 */

/**
 * Affiche le message associé au code d'erreur err suivi d'un \n sur out.
 * 
 * @param err Le code d'erreur à afficher
 */
void http_err_to_string(FILE *out, int err);

/**
 * Charge un convertisseur d'extension en MIME de chemin mime_file_path. 
 * Renvoie NULL en cas d'erreur mémoire et place *err avec un entier négatif. 
 * En cas de succès la fonction renvoie un pointeur vers un mime_finder.
 * 
 * @param mime_file_path Le chemin du fichier de conversion.
 * @param err            Un pointeur d'erreur.
 * 
 * @return               NULL en cas d'erreur mémoire ou un pointeur vers
 *                       un mime_finder en cas de succès.
 */
mime_finder *mime_finder_load(const char *mime_file_path, int *err);

/**
 * Renvoie le MIME associé à filename grâce à finder.
 * 
 * @param finder    Le MIME finder chargé par mime_finder_load.
 * @param filename  Le nom du fichier dont on souhaite récupérer le MIME.
 * 
 * @return          Le MIME en cas de succès ou NULL en cas d'erreur ou s'il 
 *                  n'est pas trouvé.
 */
const char *get_mime_type(mime_finder *finder, const char *filename);

/**
 * Libère les ressources associées à finder.
 * 
 * @param finder Le finder à libérer.
 */
void mime_finder_dispose(mime_finder **finder);

/**
 * Ecrit dans buff au maximum buff_size caractères le message correspondant au 
 * statut de numéro code. Renvoie 1 en cas de succès ou 0 si le statut n'est pas
 * trouvé.
 * 
 * @see https://datatracker.ietf.org/doc/html/rfc1945#page-26
 * 
 * @param code      Le code à convertir.
 * @param buff      La chaîne où stocker le message.
 * @param buff_size La taille maximale de buff.
 * 
 * @return          1 en cas de succès et 0 si le statut n'est pas trouvé.
 */
int status_code_to_status_msg(int code, char *buff, size_t buff_size);

#endif