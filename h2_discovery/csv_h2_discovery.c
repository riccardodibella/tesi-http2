#include <openssl/ssl.h>
#include <openssl/err.h>


#include <sys/types.h>
#include <sys/socket.h>
#include <stdio.h>
#include <errno.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <netdb.h>

#include <netinet/tcp.h>
#include <signal.h>

#define ROOT_CERT_PATH "root_ca_certs/firefox_cert_list_20230801.txt"

#define STATUS_ERR_UNKNOWN 0
#define STATUS_ERR_GETHOSTBYNAME 1
#define STATUS_ERR_CONNECT 2
#define STATUS_ERR_TLS 3
#define STATUS_HTTP_1_1 4
#define STATUS_HTTP_2 5


int excluded_ids[]={
	377,
	378,
	2165,
	2389,
	2408,
	3433,
	3827,
	4514,
	4917,
	5118,
	6016,
	6567,
	7665,
	8782,
	9226,
	9444,
	10435,
};


int main(int argc, char** argv){
	int SKIP = 0;
	int LIMIT = -1;
	if(argc <= 4){
		printf("Specificare file di input e di output, l'inizio e la fine\n");
		return 0;
	}
	
	SKIP = atoi(argv[3]);
	LIMIT = atoi(argv[4]);

	char* nome_file_input = argv[1];
	char* nome_file_output = argv[2];

	SSL* ssl;
	SSL_CTX* ssl_ctx;
	const SSL_METHOD* client_method;
	X509* peer_certificate;
	long ssl_verify_result;
	struct hostent* resolved_addr;
	struct sockaddr_in remote_addr;
	int s; // socket
	int status;

	client_method = TLS_client_method();
	ssl_ctx = SSL_CTX_new(client_method);
	if(ssl_ctx == NULL){
		perror("Errore ssl context NULL");
		ERR_print_errors_fp(stdout);
		return -1;
	}
	// In man ssl_ctx_new è scritto di fare così per evitare di usare le versioni tanto vecchie non sicure
	SSL_CTX_set_min_proto_version(ssl_ctx, TLS1_VERSION);
	
	// Impostazioni verifica certificati
	// Se si trova un problema si interrompe immediatamente l'handshake
	SSL_CTX_set_verify(ssl_ctx, SSL_VERIFY_PEER, NULL);
	
	// se si vuole finire comunque l'handshake e non chiudere la connessione anche in caso di problemi:
	// SSL_CTX_set_verify(ssl_ctx, SSL_VERIFY_NONE, NULL);
	

	if(!SSL_CTX_load_verify_locations(ssl_ctx, ROOT_CERT_PATH, NULL)){
		printf("ATTENZIONE: nessun certificato radice caricato.\n");
	}else{
		//printf("Certificati radice caricati correttamente.\n");
	}

	uint8_t alpn_protos_array[] = {
		2, 'h', '2',
		8, 'h', 't', 't', 'p', '/', '1', '.', '1'
	};
	int alpn_protos_array_length = sizeof(alpn_protos_array);
	if(!SSL_CTX_set_alpn_protos(ssl_ctx, alpn_protos_array, alpn_protos_array_length)){
		//printf("Protocolli ALPN impostati con successo\n");
	}else{
		printf("Errore impostazione protocolli ALPN\n");
		ERR_print_errors_fp(stdout);
		return -1;
	}
	//printf("Fine creazione context openssl\n");


	FILE* fp = fopen(nome_file_input, "r");
    char line[256];
    size_t len = 0;
	int char_letti;
	FILE* out = fopen(nome_file_output, "w");
	for(int i=0; i<SKIP; i++){
		fgets(line, sizeof(line), fp);
	}
	while(fgets(line, sizeof(line), fp)){

		status = STATUS_ERR_UNKNOWN;

		for(int i=0; i<strlen(line); i++){
			if(line[i]=='\n' || line[i]=='\r'){
				line[i]=0;
			}
		}
		char* server_name = line;
		while(*server_name != ','){
			server_name++;
		}
		server_name++;

		int current_id = atol(line);
		if(current_id>LIMIT){
			printf("Limite raggiunto\n");
			break;
		}
		for(int i=0; i<sizeof(excluded_ids)/sizeof(excluded_ids[0]); i++){
			if(current_id == excluded_ids[i]){
				goto write_status;
			}
		}

		if(!strncmp(server_name, "pushy-prod-", strlen("pushy-prod-"))){
			goto write_status;
		}

		// https://stackoverflow.com/a/45840521
		printf("%.*s\n", (int) strcspn(line, ","), line);

		//printf("\n-------\n");
		//printf("Server: %s\n", server_name);
		s=socket(AF_INET, SOCK_STREAM, 0);
		if (s==-1) {
			perror("Socket fallita");
			printf("%d\n",errno);
			goto write_status;
		}

		// https://stackoverflow.com/a/46473173
		int synRetries = 1;
		setsockopt(s, IPPROTO_TCP, TCP_SYNCNT, &synRetries, sizeof(synRetries));

		remote_addr.sin_family = AF_INET;
		remote_addr.sin_port = htons(443);

		resolved_addr = gethostbyname(server_name);
		if(!resolved_addr){
			//printf("Gethostbyname fallita\n");
			status = STATUS_ERR_GETHOSTBYNAME;
			close(s);
			goto write_status;
		}
		remote_addr.sin_addr.s_addr = *(unsigned int*) resolved_addr->h_addr_list[0];
		//printf("Prima di connect\n");
		if(connect(s,(struct sockaddr *) &remote_addr,sizeof(struct sockaddr_in)) ==-1) {
			//perror("Connect Fallita");
			status = STATUS_ERR_CONNECT;
			close(s);
			goto write_status;
		}
		//printf("Connect ok\n");
		


		ssl = SSL_new(ssl_ctx);
		if(ssl==NULL){
			perror("Errore ssl SSL_new NULL");
			ERR_print_errors_fp(stdout);
			close(s);
			goto write_status;
		}
		SSL_set_tlsext_host_name(ssl, server_name);
		if(!SSL_set_fd(ssl, s)){
			perror("Errore SSL set fd");
			ERR_print_errors_fp(stdout);
			SSL_shutdown(ssl);
			close(s);
			SSL_free(ssl);
			goto write_status;
		}
		
		//printf("Prima di SSL_connect\n");
		if(SSL_connect(ssl)!=1){
			//printf("SSL connect fallita\n");
			//perror("Errore");
			//ERR_print_errors_fp(stdout);
			//printf("ssl_get_verify_result: %ld\n", SSL_get_verify_result(ssl));
			status = STATUS_ERR_TLS;
			SSL_shutdown(ssl);
			close(s);
			SSL_free(ssl);
			goto write_status;
		}
		//printf("Dopo SSL_connect\n");
		/*
		peer_certificate = SSL_get_peer_certificate(ssl);
		if(peer_certificate == NULL){
			printf("peer certificate NULL");
		}else{		
			X509_free(peer_certificate);
		}
		printf("Dopo ottenimento certificato\n");
		ssl_verify_result = SSL_get_verify_result(ssl);
		if(ssl_verify_result != X509_V_OK){
			printf("SSL verify result != X509_V_OK -> s_v_r = %ld\n",ssl_verify_result);
		}else{
			printf("SSL verify result == X509_V_OK\n");
		}
		*/
		//printf("Connessione SSL effettuata\n");

		int alpn_selected_length;
		char* alpn_selected_name;
		SSL_get0_alpn_selected(ssl, (const unsigned char **) &alpn_selected_name, &alpn_selected_length);
		
		/*printf("Selected ALPN protocol: ");
		for(int i=0; i<alpn_selected_length; i++){
			printf("%c", alpn_selected_name[i]);
		}
		printf("\n");*/
		
		if(alpn_selected_length==2&&alpn_selected_name[0]=='h'&&alpn_selected_name[1]=='2'){
			//printf("HTTP/2 SELEZIONATO\n");
			status = STATUS_HTTP_2;
		}else{
			//printf("HTTP/2 NON SUPPORTATO\n");
			status = STATUS_HTTP_1_1;
		}
		SSL_shutdown(ssl);
		close(s);
		SSL_free(ssl);

		write_status:
		fprintf(out, "%s,%d\n", line, status);
		fflush(out);
	}
	SSL_CTX_free(ssl_ctx);
	fclose(fp);
	fclose(out);
}
