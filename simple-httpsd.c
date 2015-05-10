#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <errno.h>
#include <string.h>
#include <sys/types.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <pthread.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

#define MAX_BUF 1024
#define MAX_HTTP_SIZE 1024*1024*1
uint32_t port = 8080;
uint32_t listen_num = 5;
SSL_CTX *ctx;

#define THREAD_NUM 3
struct thread_info {
    pthread_t tid;
    long count;
};
struct thread_info thread_infos[THREAD_NUM];

#define MAXCONN 32
int connfds[MAXCONN], iput, iget;
pthread_mutex_t connfd_mutex = PTHREAD_MUTEX_INITIALIZER;
pthread_cond_t connfd_cond = PTHREAD_COND_INITIALIZER;

/**
 * Linear string search based on memcmp()
 */
char * search_linear(char *needle, char *haystack, uint32_t needle_len, uint32_t haystack_len)
{
    char *k = haystack + (haystack_len - needle_len);
    char *t = haystack;
	
    if (needle_len == 0) {
        return NULL;
    }
    while (t <= k) {
        if (memcmp(t, needle, needle_len) == 0) {
            return t;
        }
        t ++;
    }
    return NULL;
}

/**
 * Fetch the data between two pattern
 */
int mem_parse(char *buf, char *mp1, char *mp2,
                uint32_t buf_len, uint32_t mp1_len, uint32_t mp2_len, char *dbuf, uint32_t dlen)
{
	
    char *src = NULL, *dst = NULL;
    int i = 0;
    int len = -1;
    
    if (mp1_len > 0) {
        src = search_linear(mp1, buf, mp1_len, buf_len);
        if (src != NULL) {
            if (mp2_len > 0) {
                src += mp1_len;
                if ((dst = search_linear(mp2, src, mp2_len, buf_len - ((unsigned long)src - (unsigned long)buf))) != NULL) {
                    if ((len = (unsigned long)dst - (unsigned long)src) > (dlen -1)) { 
                        len = dlen - 1;
                    }
                    for (i = 0; i < len; i++) {
                        *(dbuf + i) = *(src + i);
                    }      
                    *(dbuf + i) = '\0';
                }
            }
            else {
                src += mp1_len;
                len = buf_len - ((unsigned long)src - (unsigned long)buf); 
                if (len > (dlen - 1)) {
                    len = dlen - 1;
                }
                for (i = 0; i < len; i++) {
                    *(dbuf + i) = *(src + i);
                }
                *(dbuf + i) = '\0';		
            }
        }
    }
    
    return len;
}


void write_file(char *path, char *buf, int buf_len)
{
    int fd;
    if ((fd = open(path, O_CREAT|O_TRUNC|O_RDWR, S_IRWXU)) < 0) {
        perror("can't open file");
        return; 
    }
    write(fd, buf, buf_len);
    close(fd);
}

static char time_str[64];
char *now(void)
{
    time_t t;
    struct tm     *tm = NULL;

    time(&t);
    tm = localtime(&t);
    memset(time_str, 0, 64);

    snprintf(time_str, 64, "%d-%d-%d-%d-%d-%d", (1900+tm->tm_year),
             (1+tm->tm_mon),
             tm->tm_mday,
             tm->tm_hour,
             tm->tm_min,
             tm->tm_sec);
    return time_str;
}

void printids(const char *s)
{
    pid_t pid;
    pthread_t tid;

    pid = getpid();
    tid = pthread_self();
    printf("%s pid %u tid %u (0x%x) \n", 
           s, 
           (unsigned int)pid,
           (unsigned int)tid,
           (unsigned int)tid);
}

int handle_https(int new_fd)
{
    SSL *ssl;
    char buf[MAX_BUF], http[MAX_HTTP_SIZE];
    int http_len, ret;

    // create a new ssl based on ctx
    ssl = SSL_new(ctx);
    // add socket into ssl
    SSL_set_fd(ssl, new_fd);
    // create ssl connection
    if (SSL_accept(ssl) == -1) {
        perror("SSL_accept");
        close(new_fd);
        return -1;
    }


    char *ptr = NULL;
    http_len = 0;
    int header_ready, total_len, header_len, body_len;
    header_ready = 0;
    char content_len_buf[32];
    bzero(content_len_buf, 32);
    while (1) {
        // receiving message
        if ((ret = SSL_read(ssl, buf, MAX_BUF)) < 0) {
            printf("failing to read messages: errno=%d，errmsg=%s\n", errno, strerror(errno));
            goto finish;
        }
        //printf("%s", buf);
        memcpy(http + http_len, buf, ret);
        http_len += ret;
        if (!header_ready) {
            if ((ptr = search_linear("\r\n\r\n", http, 4, http_len)) != NULL) {
                header_len = (unsigned long)ptr - (unsigned long)http;
                header_ready = 1;
                // curl
                //mem_parse(http, "Content-Length: ", "\r\n", header_len, 16, 2, content_len_buf, 32);
                // ab
                mem_parse(http, "Content-length: ", "\r\n", header_len, 16, 2, content_len_buf, 32);
                body_len = atoi(content_len_buf);
                total_len = header_len + 4 + body_len;
            }
        }
        if (http_len == total_len) {
            printf("recv completely\n");
            break;
        }
    }
    // store the whole http request for debug
    write_file("/tmp/http", http, http_len);

    // create file
    // only handle the use case: one form_data
    char boundary[MAX_BUF], filename[MAX_BUF], form_data[MAX_HTTP_SIZE];
    int boundary_len, form_data_len;
    memset(boundary, 0, MAX_BUF);
    memset(filename, 0, MAX_BUF);
    memset(form_data, 0, MAX_HTTP_SIZE);
    boundary_len = mem_parse(http, "boundary=", "\r\n", header_len+4, 9, 2, boundary, MAX_BUF);
    form_data_len = mem_parse(http + header_len + 4, boundary, boundary, body_len, boundary_len, boundary_len, form_data, MAX_HTTP_SIZE);
    mem_parse(form_data, "filename=\"", "\"\r\n", form_data_len, 10, 3, filename, MAX_BUF);
    char *filebuf_ptr;
    int filebuf_len;	
    if (!(filebuf_ptr = search_linear("\r\n\r\n", form_data, 4, form_data_len)))
        goto finish;
    filebuf_ptr += 4;
    filebuf_len = form_data_len - ((unsigned long)filebuf_ptr - (unsigned long)form_data) - 4;
        
    // only support english filename
    char new_file[MAX_BUF];
    memset(new_file, 0, MAX_BUF);
    snprintf(new_file, MAX_BUF, "/tmp/%s-%s", filename, now());
    printf("new_file:%s\n", new_file);
    write_file(new_file, filebuf_ptr, filebuf_len);
        
    bzero(buf, MAX_BUF);
    snprintf(buf, MAX_BUF, "HTTP/1.1 200 OK\r\nContent-Type: text/octet\r\nContent-Length: 25\r\n\r\nUpload file successfully\n");
    // sending message
    if ((ret = SSL_write(ssl, buf, strlen(buf))) < 0) {
        printf("failing to read messages: errno=%d，errmsg=%s\n", errno, strerror(errno));
    }

finish:
    SSL_shutdown(ssl);
    SSL_free(ssl);
    close(new_fd);
    return 0;
}

void *thread_main(void *arg)
{
    int connfd;

    for ( ; ; ) {
        pthread_mutex_lock(&connfd_mutex);
        while (iget == iput) 
            pthread_cond_wait(&connfd_cond, &connfd_mutex);
        connfd = connfds[iget];
        if (++iget == MAXCONN)
            iget = 0;
        pthread_mutex_unlock(&connfd_mutex);
        printids("handle_https: ");
        thread_infos[(int)arg].count ++;
        handle_https(connfd);
    }
}
int main(int argc, char **argv)
{
    int sockfd, new_fd;
    socklen_t len;
    struct sockaddr_in local_addr, peer_addr;

    // init ssl
    SSL_library_init();
    OpenSSL_add_all_algorithms();
    SSL_load_error_strings();
    if ((ctx = SSL_CTX_new(SSLv23_server_method())) == NULL) {
        ERR_print_errors_fp(stdout);
        exit(1);
    }
    if (SSL_CTX_use_certificate_file(ctx, "./ca.pem", SSL_FILETYPE_PEM) <= 0) {
        ERR_print_errors_fp(stdout);
        exit(1);
    }
    if (SSL_CTX_use_PrivateKey_file(ctx, "./private-key.pem", SSL_FILETYPE_PEM) <= 0) {
        ERR_print_errors_fp(stdout);
        exit(1);
    }
    if (!SSL_CTX_check_private_key(ctx)) {
        ERR_print_errors_fp(stdout);
        exit(1);
    }

    // init socket
    if ((sockfd = socket(PF_INET, SOCK_STREAM, 0)) == -1) {
        perror("socket");
        exit(1);
    }
     
    bzero(&local_addr, sizeof(local_addr));
    local_addr.sin_family = PF_INET;
    local_addr.sin_port = htons(port);
    local_addr.sin_addr.s_addr = INADDR_ANY;

    if (bind(sockfd, (struct sockaddr *) &local_addr, sizeof(struct sockaddr)) == -1) {
        perror("bind");
        exit(1);
    }
     
    if (listen(sockfd, listen_num) == -1) {
        perror("listen");
        exit(1);
    }

    // alloc threads
    iput = iget = 0;
    int i = 0;
    for (i = 0; i < THREAD_NUM; i++) {
        int err;
        if ((err = pthread_create(&thread_infos[i].tid, NULL, thread_main, (void *)i)) < 0) {
            perror("pthread_create");
        }
    }
    // only handle the user case: per post per connection
    while (1) {
        len = sizeof(struct sockaddr);
        // waitting for client
        if ((new_fd = accept(sockfd, (struct sockaddr *) &peer_addr, &len)) == -1) {
            perror("accept");
            exit(errno);
        } 
        else {
            printf("server: got connection from %s, port %d, socket %d\n",
                   inet_ntoa(peer_addr.sin_addr),
                   ntohs(peer_addr.sin_port), new_fd);
        }
        pthread_mutex_lock(&connfd_mutex);
        connfds[iput] = new_fd;
        if (++iput == MAXCONN) {
            iput = 0;
        }
        if (iput == iget) {
            printf("iput = iget = %d\n", iput);
        }
        pthread_cond_signal(&connfd_cond);
        pthread_mutex_unlock(&connfd_mutex);
    }

    close(sockfd);
    SSL_CTX_free(ctx);
    return 0;
}
