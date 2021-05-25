#ifndef _HTTTP_TOOL_H
#define _HTTTP_TOOL_H

typedef struct http_result http_result_t;

#ifdef __cplusplus

extern "C"{
#endif

http_result_t* http_get(const char* url);
http_result_t* http_post(const char* url, const char* data);
http_result_t* http_post_json(const char* url, const char** data, int len);
char* rsa_public_encrypt(const char* pubkey, const char* data);
char* aes_encrypt(const char* data, const char* key);
char* aes_decrypt(const char* data, const char* key);
char* aes_random_key128();
void free_string(char* str);
void http_result_free(http_result_t *);
int http_result_success(http_result_t *);
char* http_result_status_info(http_result_t *);
char* http_result_content(http_result_t *, const char* charset);
char* http_result_error_info(http_result_t *, const char* charset);
void printval(const char* str1, const char* str2);

#ifdef __cplusplus
}
#endif
#endif