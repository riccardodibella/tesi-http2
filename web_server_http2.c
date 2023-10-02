#define _GNU_SOURCE

#include <openssl/ssl.h>
#include <openssl/err.h>

#include <arpa/inet.h>

#include <sys/socket.h>
#include <sys/types.h>
#include <sys/ioctl.h>
#include <sys/wait.h>
#include <sys/un.h>

#include <string.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdio.h>
#include <fcntl.h>
#include <errno.h>
#include <ctype.h>
#include <poll.h>

#define NO_DEBUG

#ifdef NO_DEBUG
#define printf(...)
#define perror(...)
#define ERR_print_errors_fp(...)
#endif

#define REQUEST_LINE_BUFFER_SIZE 1000
#define HEADER_LIST_SIZE 1000
#define REQUEST_HEADER_BUFFER_SIZE 100000
#define TEMP_RESOURCE_BUFFER_SIZE 100000000
#define PUSH_FILE_LINE_BUFFER_SIZE 100

#define IPC_MSG_KERNEL_BUFFER_SIZE 0x40000000L // per setsockopt SO_SNDBUF e SO_RCVBUF
#define MAX_IPC_SEND_ATTEMPT_COUNT 1000
#define COMMAND_SOCKET_PATH_TEMPLATE "command_socket_%d.socket"
#define URGENT_SOCKET_PATH_TEMPLATE "urgent_socket_%d.socket"
#define HEADERS_SOCKET_PATH_TEMPLATE "headers_socket_%d.socket"
#define DATA_SOCKET_PATH_TEMPLATE "data_socket_%d.socket"
#define NEW_STREAM_SOCKET_PATH_TEMPLATE "new_stream_socket_%d.socket" // Creato in obtain_new_stream_id 
#define NEW_STREAM_ID_CMD_TEMPLATE "NEW_STREAM_ID %s"
#define NEW_STREAM_ID_CMD_PREFIX "NEW_STREAM_ID "

#define CONNECTION_PREFACE_BUFFER_SIZE 25
#define EXPECTED_CONNECTION_PREFACE "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"
#define RET_TRUE 1
#define RET_FALSE 0

#define FRAME_TYPE_DATA 0x00
#define FRAME_TYPE_HEADERS 0x01
#define FRAME_TYPE_PRIORITY 0x02
#define FRAME_TYPE_RST_STREAM 0x03
#define FRAME_TYPE_SETTINGS 0x04
#define FRAME_TYPE_PUSH_PROMISE 0x05
#define FRAME_TYPE_PING 0x06
#define FRAME_TYPE_GOAWAY 0x07
#define FRAME_TYPE_WINDOW_UPDATE 0x08
#define FRAME_TYPE_CONTINUATION 0x09
#define FRAME_TYPE_PRIORITY_UPDATE 0x10

#define SETTINGS_HEADER_TABLE_SIZE 0x01
#define SETTINGS_ENABLE_PUSH 0x02
#define SETTINGS_MAX_CONCURRENT_STREAMS 0x03
#define SETTINGS_INITIAL_WINDOW_SIZE 0x04
#define SETTINGS_MAX_FRAME_SIZE 0x05
#define SETTINGS_MAX_HEADER_LIST_SIZE 0x06
#define SETTINGS_NO_RFC7540_PRIORITIES 0x09

#define FLAG_PRIORITY		0b00100000
#define FLAG_PADDED			0b00001000
#define FLAG_END_HEADERS	0b00000100
#define FLAG_END_STREAM		0b00000001
#define FLAG_ACK 			0b00000001

#define STATIC_HEADER_TABLE_SIZE 61

#define DEFAULT_INITIAL_FLOW_CONTROL_WINDOW_SIZE 65535	// Definita nello standard
#define DEFAULT_HEADER_TABLE_SIZE 4096 					// Definita nello standard
#define INITIAL_SERVER_HEADER_TABLE_SIZE DEFAULT_HEADER_TABLE_SIZE // Come impostazione iniziale trasmessa dal server uso il valore di default

#define HTTP_1_1_400_RESPONSE "HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\n\r\n"
#define HTTP_1_1_404_RESPONSE "HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n"
#define HTTP_1_1_500_RESPONSE "HTTP/1.1 500 Internal Server Error\r\nContent-Length: 0\r\n\r\n"
#define HTTP_1_1_200_RESPONSE_HEADERS "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n"

#define MIN_H2_READ_BYTE_BUFFER_CAPACITY 1024

#define READ_RESULT_OK 1
#define READ_RESULT_ERROR 2
#define READ_RESULT_NOTHING 3



/*
	CONFIGURAZIONI
*/
#define PUSH_LIST_FILE_SUFFIX ".push"
#define HTTPS_PRIVATE_KEY_PATH "./certificati_https/certs/web-server-h2.duckdns.org/privkey.pem"
#define HTTPS_CERTIFICATE_PATH "./certificati_https/certs/web-server-h2.duckdns.org/cert.pem"
#define SERVER_PORT 9000
#define QUEUE_LENGTH 10
#define HOMEPAGE_FILENAME "index.html" // Viene usato questo file quando la request è "/"
#define WEBSITE_ROOT_DIRECTORY "./wwwroot/"
#define SERVER_AUTHORITY "web-server-h2.duckdns.org:9000"

/*
	PARAMETRI
*/
#define H2_ENABLED 1
#define USE_PUSH_IF_ENABLED 1
#define DATA_FRAME_PAYLOAD_SIZE 4096
#define FORCE_FULL_DATA_FRAME 0
#define CHUNK_MAX_LENGTH 8192



struct http_header{
	char* nome;
	char* valore;
};
struct header_list_node{
	struct http_header* node_header;
	struct header_list_node* next_node;
};

struct logical_frame_header{
	uint32_t length; // NB solo 24 bit sono usati
	uint8_t type;
	uint8_t flags;
	uint32_t stream_identifier; // NB primo bit è riservato
};

struct wire_frame_header{
	uint8_t length_arr[3];
	uint8_t type;
	uint8_t flags;
	uint8_t stream_id_arr[4];
};

struct logical_frame_wire_payload{
	struct logical_frame_header header;
	uint8_t* payload;
};
struct full_frame_list_node{
	struct logical_frame_wire_payload frame;
	struct full_frame_list_node* next;
};

struct logical_setting{
	uint16_t id;
	uint32_t value;
};

struct wire_setting{
	uint8_t id_arr[2];
	uint8_t value_arr[4];
};

struct dynamic_table_entry{
	uint8_t* header_name;
	uint8_t* header_value;
	struct dynamic_table_entry* next_entry;
};

struct sockaddr_in local_addr, remote_addr;

char client_settings_frame_received = 0; // bool
char server_settings_ack_received = 0; // bool

uint32_t client_header_table_size = DEFAULT_HEADER_TABLE_SIZE; // usato in HTTP/2

char push_enabled = 1; // bool

uint32_t client_max_concurrent_streams = 0x7FFFFFFF; // Inizialmente il valore è illimitato (questo è il limite superiore id stream)

uint32_t client_max_frame_size = 16384;

char client_max_header_list_size_specified = 0; // bool
uint32_t client_max_header_list_size;

int connection_socket_identifier;


// Variabili di stato HPACK
uint32_t current_dynamic_table_capacity = DEFAULT_HEADER_TABLE_SIZE; //4096 valore iniziale, viene aggiornato con i dynamic table size update
struct dynamic_table_entry dynamic_table_head = { .header_name=NULL, .header_value=NULL, .next_entry=NULL }; // la next_entry di questa è il primo elemento della lista


struct http_header static_header_table[STATIC_HEADER_TABLE_SIZE]={

	// Gli indici da usare sono 1+l'indice in questo array

	[0]=	{.nome = ":authority", .valore = NULL},
	[1]=	{.nome = ":method", .valore = "GET"},
	[2]=	{.nome = ":method", .valore = "POST"},
	[3]=	{.nome = ":path", .valore = "/"},
	[4]=	{.nome = ":path", .valore = "/index.html"},
	[5]=	{.nome = ":scheme", .valore = "http"},
	[6]=	{.nome = ":scheme", .valore = "https"},
	[7]=	{.nome = ":status", .valore = "200"},
	[8]=	{.nome = ":status", .valore = "204"},
	[9]=	{.nome = ":status", .valore = "206"},
	[10]=	{.nome = ":status", .valore = "304"},
	[11]=	{.nome = ":status", .valore = "400"},
	[12]=	{.nome = ":status", .valore = "404"},
	[13]=	{.nome = ":status", .valore = "500"},
	[14]=	{.nome = "accept-charset", .valore = ""},
	[15]=	{.nome = "accept-encoding", .valore = "gzip, deflate"},
	[16]=	{.nome = "accept-language", .valore = NULL},
	[17]=	{.nome = "accept-ranges", .valore = NULL},
	[18]=	{.nome = "accept", .valore = NULL},
	[19]=	{.nome = "access-control-allow-origin", .valore = NULL},
	[20]=	{.nome = "age", .valore = NULL},
	[21]=	{.nome = "allow", .valore = NULL},
	[22]=	{.nome = "authorization", .valore = NULL},
	[23]=	{.nome = "cache-control", .valore = NULL},
	[24]=	{.nome = "content-disposition", .valore = NULL},
	[25]=	{.nome = "content-encoding", .valore = NULL},
	[26]=	{.nome = "content-language", .valore = NULL},
	[27]=	{.nome = "content-length", .valore = NULL},
	[28]=	{.nome = "content-location", .valore = NULL},
	[29]=	{.nome = "content-range", .valore = NULL},
	[30]=	{.nome = "content-type", .valore = NULL},
	[31]=	{.nome = "cookie", .valore = NULL},
	[32]=	{.nome = "date", .valore = NULL},
	[33]=	{.nome = "etag", .valore = NULL},
	[34]=	{.nome = "expect", .valore = NULL},
	[35]=	{.nome = "expires", .valore = NULL},
	[36]=	{.nome = "from", .valore = NULL},
	[37]=	{.nome = "host", .valore = NULL},
	[38]=	{.nome = "if-match", .valore = NULL},
	[39]=	{.nome = "if-modified-since", .valore = NULL},
	[40]=	{.nome = "if-none-match", .valore = NULL},
	[41]=	{.nome = "if-range", .valore = NULL},
	[42]=	{.nome = "if-unmodified-since", .valore = NULL},
	[43]=	{.nome = "last-modified", .valore = NULL},
	[44]=	{.nome = "link", .valore = NULL},
	[45]=	{.nome = "location", .valore = NULL},
	[46]=	{.nome = "max-forwards", .valore = NULL},
	[47]=	{.nome = "proxy-authenticate", .valore = NULL},
	[48]=	{.nome = "proxy-authorization", .valore = NULL},
	[49]=	{.nome = "range", .valore = NULL},
	[50]=	{.nome = "referer", .valore = NULL},
	[51]=	{.nome = "refresh", .valore = NULL},
	[52]=	{.nome = "retry-after", .valore = NULL},
	[53]=	{.nome = "server", .valore = NULL},
	[54]=	{.nome = "set-cookie", .valore = NULL},
	[55]=	{.nome = "strict-transport-security", .valore = NULL},
	[56]=	{.nome = "transfer-encoding", .valore = NULL},
	[57]=	{.nome = "user-agent", .valore = NULL},
	[58]=	{.nome = "vary", .valore = NULL},
	[59]=	{.nome = "via", .valore = NULL},
	[60]=	{.nome = "www-authenticate", .valore = NULL},
};

char* huffman_table[]={
	[0]		=	"1111111111000",
	[1]		=	"11111111111111111011000",
	[2]		=	"1111111111111111111111100010",
	[3]		=	"1111111111111111111111100011",
	[4]		=	"1111111111111111111111100100",
	[5]		=	"1111111111111111111111100101",
	[6]		=	"1111111111111111111111100110",
	[7]		=	"1111111111111111111111100111",
	[8]		=	"1111111111111111111111101000",
	[9]		=	"111111111111111111101010",
	[10]	=	"111111111111111111111111111100",
	[11]	=	"1111111111111111111111101001",
	[12]	=	"1111111111111111111111101010",
	[13]	=	"111111111111111111111111111101",
	[14]	=	"1111111111111111111111101011",
	[15]	=	"1111111111111111111111101100",
	[16]	=	"1111111111111111111111101101",
	[17]	=	"1111111111111111111111101110",
	[18]	=	"1111111111111111111111101111",
	[19]	=	"1111111111111111111111110000",
	[20]	=	"1111111111111111111111110001",
	[21]	=	"1111111111111111111111110010",
	[22]	=	"111111111111111111111111111110",
	[23]	=	"1111111111111111111111110011",
	[24]	=	"1111111111111111111111110100",
	[25]	=	"1111111111111111111111110101",
	[26]	=	"1111111111111111111111110110",
	[27]	=	"1111111111111111111111110111",
	[28]	=	"1111111111111111111111111000",
	[29]	=	"1111111111111111111111111001",
	[30]	=	"1111111111111111111111111010",
	[31]	=	"1111111111111111111111111011",
	[32]	=	"010100",
	[33]	=	"1111111000",
	[34]	=	"1111111001",
	[35]	=	"111111111010",
	[36]	=	"1111111111001",
	[37]	=	"010101",
	[38]	=	"11111000",
	[39]	=	"11111111010",
	[40]	=	"1111111010",
	[41]	=	"1111111011",
	[42]	=	"11111001",
	[43]	=	"11111111011",
	[44]	=	"11111010",
	[45]	=	"010110",
	[46]	=	"010111",
	[47]	=	"011000",
	[48]	=	"00000",
	[49]	=	"00001",
	[50]	=	"00010",
	[51]	=	"011001",
	[52]	=	"011010",
	[53]	=	"011011",
	[54]	=	"011100",
	[55]	=	"011101",
	[56]	=	"011110",
	[57]	=	"011111",
	[58]	=	"1011100",
	[59]	=	"11111011",
	[60]	=	"111111111111100",
	[61]	=	"100000",
	[62]	=	"111111111011",
	[63]	=	"1111111100",
	[64]	=	"1111111111010",
	[65]	=	"100001",
	[66]	=	"1011101",
	[67]	=	"1011110",
	[68]	=	"1011111",
	[69]	=	"1100000",
	[70]	=	"1100001",
	[71]	=	"1100010",
	[72]	=	"1100011",
	[73]	=	"1100100",
	[74]	=	"1100101",
	[75]	=	"1100110",
	[76]	=	"1100111",
	[77]	=	"1101000",
	[78]	=	"1101001",
	[79]	=	"1101010",
	[80]	=	"1101011",
	[81]	=	"1101100",
	[82]	=	"1101101",
	[83]	=	"1101110",
	[84]	=	"1101111",
	[85]	=	"1110000",
	[86]	=	"1110001",
	[87]	=	"1110010",
	[88]	=	"11111100",
	[89]	=	"1110011",
	[90]	=	"11111101",
	[91]	=	"1111111111011",
	[92]	=	"1111111111111110000",
	[93]	=	"1111111111100",
	[94]	=	"11111111111100",
	[95]	=	"100010",
	[96]	=	"111111111111101",
	[97]	=	"00011",
	[98]	=	"100011",
	[99]	=	"00100",
	[100]	=	"100100",
	[101]	=	"00101",
	[102]	=	"100101",
	[103]	=	"100110",
	[104]	=	"100111",
	[105]	=	"00110",
	[106]	=	"1110100",
	[107]	=	"1110101",
	[108]	=	"101000",
	[109]	=	"101001",
	[110]	=	"101010",
	[111]	=	"00111",
	[112]	=	"101011",
	[113]	=	"1110110",
	[114]	=	"101100",
	[115]	=	"01000",
	[116]	=	"01001",
	[117]	=	"101101",
	[118]	=	"1110111",
	[119]	=	"1111000",
	[120]	=	"1111001",
	[121]	=	"1111010",
	[122]	=	"1111011",
	[123]	=	"111111111111110",
	[124]	=	"11111111100",
	[125]	=	"11111111111101",
	[126]	=	"1111111111101",
	[127]	=	"1111111111111111111111111100",
	[128]	=	"11111111111111100110",
	[129]	=	"1111111111111111010010",
	[130]	=	"11111111111111100111",
	[131]	=	"11111111111111101000",
	[132]	=	"1111111111111111010011",
	[133]	=	"1111111111111111010100",
	[134]	=	"1111111111111111010101",
	[135]	=	"11111111111111111011001",
	[136]	=	"1111111111111111010110",
	[137]	=	"11111111111111111011010",
	[138]	=	"11111111111111111011011",
	[139]	=	"11111111111111111011100",
	[140]	=	"11111111111111111011101",
	[141]	=	"11111111111111111011110",
	[142]	=	"111111111111111111101011",
	[143]	=	"11111111111111111011111",
	[144]	=	"111111111111111111101100",
	[145]	=	"111111111111111111101101",
	[146]	=	"1111111111111111010111",
	[147]	=	"11111111111111111100000",
	[148]	=	"111111111111111111101110",
	[149]	=	"11111111111111111100001",
	[150]	=	"11111111111111111100010",
	[151]	=	"11111111111111111100011",
	[152]	=	"11111111111111111100100",
	[153]	=	"111111111111111011100",
	[154]	=	"1111111111111111011000",
	[155]	=	"11111111111111111100101",
	[156]	=	"1111111111111111011001",
	[157]	=	"11111111111111111100110",
	[158]	=	"11111111111111111100111",
	[159]	=	"111111111111111111101111",
	[160]	=	"1111111111111111011010",
	[161]	=	"111111111111111011101",
	[162]	=	"11111111111111101001",
	[163]	=	"1111111111111111011011",
	[164]	=	"1111111111111111011100",
	[165]	=	"11111111111111111101000",
	[166]	=	"11111111111111111101001",
	[167]	=	"111111111111111011110",
	[168]	=	"11111111111111111101010",
	[169]	=	"1111111111111111011101",
	[170]	=	"1111111111111111011110",
	[171]	=	"111111111111111111110000",
	[172]	=	"111111111111111011111",
	[173]	=	"1111111111111111011111",
	[174]	=	"11111111111111111101011",
	[175]	=	"11111111111111111101100",
	[176]	=	"111111111111111100000",
	[177]	=	"111111111111111100001",
	[178]	=	"1111111111111111100000",
	[179]	=	"111111111111111100010",
	[180]	=	"11111111111111111101101",
	[181]	=	"1111111111111111100001",
	[182]	=	"11111111111111111101110",
	[183]	=	"11111111111111111101111",
	[184]	=	"11111111111111101010",
	[185]	=	"1111111111111111100010",
	[186]	=	"1111111111111111100011",
	[187]	=	"1111111111111111100100",
	[188]	=	"11111111111111111110000",
	[189]	=	"1111111111111111100101",
	[190]	=	"1111111111111111100110",
	[191]	=	"11111111111111111110001",
	[192]	=	"11111111111111111111100000",
	[193]	=	"11111111111111111111100001",
	[194]	=	"11111111111111101011",
	[195]	=	"1111111111111110001",
	[196]	=	"1111111111111111100111",
	[197]	=	"11111111111111111110010",
	[198]	=	"1111111111111111101000",
	[199]	=	"1111111111111111111101100",
	[200]	=	"11111111111111111111100010",
	[201]	=	"11111111111111111111100011",
	[202]	=	"11111111111111111111100100",
	[203]	=	"111111111111111111111011110",
	[204]	=	"111111111111111111111011111",
	[205]	=	"11111111111111111111100101",
	[206]	=	"111111111111111111110001",
	[207]	=	"1111111111111111111101101",
	[208]	=	"1111111111111110010",
	[209]	=	"111111111111111100011",
	[210]	=	"11111111111111111111100110",
	[211]	=	"111111111111111111111100000",
	[212]	=	"111111111111111111111100001",
	[213]	=	"11111111111111111111100111",
	[214]	=	"111111111111111111111100010",
	[215]	=	"111111111111111111110010",
	[216]	=	"111111111111111100100",
	[217]	=	"111111111111111100101",
	[218]	=	"11111111111111111111101000",
	[219]	=	"11111111111111111111101001",
	[220]	=	"1111111111111111111111111101",
	[221]	=	"111111111111111111111100011",
	[222]	=	"111111111111111111111100100",
	[223]	=	"111111111111111111111100101",
	[224]	=	"11111111111111101100",
	[225]	=	"111111111111111111110011",
	[226]	=	"11111111111111101101",
	[227]	=	"111111111111111100110",
	[228]	=	"1111111111111111101001",
	[229]	=	"111111111111111100111",
	[230]	=	"111111111111111101000",
	[231]	=	"11111111111111111110011",
	[232]	=	"1111111111111111101010",
	[233]	=	"1111111111111111101011",
	[234]	=	"1111111111111111111101110",
	[235]	=	"1111111111111111111101111",
	[236]	=	"111111111111111111110100",
	[237]	=	"111111111111111111110101",
	[238]	=	"11111111111111111111101010",
	[239]	=	"11111111111111111110100",
	[240]	=	"11111111111111111111101011",
	[241]	=	"111111111111111111111100110",
	[242]	=	"11111111111111111111101100",
	[243]	=	"11111111111111111111101101",
	[244]	=	"111111111111111111111100111",
	[245]	=	"111111111111111111111101000",
	[246]	=	"111111111111111111111101001",
	[247]	=	"111111111111111111111101010",
	[248]	=	"111111111111111111111101011",
	[249]	=	"1111111111111111111111111110",
	[250]	=	"111111111111111111111101100",
	[251]	=	"111111111111111111111101101",
	[252]	=	"111111111111111111111101110",
	[253]	=	"111111111111111111111101111",
	[254]	=	"111111111111111111111110000",
	[255]	=	"11111111111111111111101110",
	[256]	=	"111111111111111111111111111111",
};





char* error_description_from_code(uint32_t error_code){
	// Ritorna una stringa con la descrizione dell'errore partendo dal codice numerico
	// NON FARE FREE DELLA STRINGA RITORNATA

	// https://www.rfc-editor.org/rfc/rfc9113#name-error-codes
	switch (error_code){
		case 0x00:
			return "NO_ERROR";
		case 0x01:
			return "PROTOCOL_ERROR";
		case 0x02:
			return "INTERNAL_ERROR";
		case 0x03:
			return "FLOW_CONTROL_ERROR";
		case 0x04:
			return "SETTINGS_TIMEOUT";
		case 0x05:
			return "STREAM_CLOSED";
		case 0x06:
			return "FRAME_SIZE_ERROR";
		case 0x07:
			return "REFUSED_STREAM";
		case 0x08:
			return "CANCEL";
		case 0x09:
			return "COMPRESSION_ERROR";
		case 0x0a:
			return "CONNECT_ERROR";
		case 0x0b:
			return "ENHANCE_YOUR_CALM";
		case 0x0c:
			return "INADEQUATE_SECURITY";
		case 0x0d:
			return "HTTP_1_1_REQUIRED";
		default:
			return "UNKNOWN_ERROR_CODE";
	}
}

uint32_t length_from_wire_frame_header(const struct wire_frame_header* ptr){
	return (*ptr).length_arr[0] << 16 | (*ptr).length_arr[1] << 8 | (*ptr).length_arr[2];
}

uint32_t stream_id_from_wire_frame_header(const struct wire_frame_header* ptr){
	return ((*ptr).stream_id_arr[0] & 0x7F) << 24 | (*ptr).stream_id_arr[1] << 16 | (*ptr).stream_id_arr[2] << 8 | (*ptr).stream_id_arr[3];
}

uint16_t id_from_wire_setting(const struct wire_setting* ptr){
	return (*ptr).id_arr[0] << 8 | (*ptr).id_arr[1];
}

uint32_t value_from_wire_setting(const struct wire_setting* ptr){
	return (*ptr).value_arr[0] << 24 | (*ptr).value_arr[1] << 16 | (*ptr).value_arr[2] << 8 | (*ptr).value_arr[3];
}

void wire_to_logical_setting(const struct wire_setting* w, struct logical_setting* l){
	l->id = id_from_wire_setting(w);
	l->value = value_from_wire_setting(w);
}

void logical_to_wire_setting(const struct logical_setting* l, struct wire_setting* w){
	w->id_arr[0] = l->id/256;
	w->id_arr[1] = l->id%256;

	uint32_t conv = htonl(l->value);
	uint8_t* ptr = (uint8_t*)&conv;
	w->value_arr[0] = ptr[0];
	w->value_arr[3] = ptr[3];
	w->value_arr[1] = ptr[1];
	w->value_arr[2] = ptr[2];
}

void wire_to_logical_frame_header(const struct wire_frame_header* w, struct logical_frame_header* l){
	l->type = w->type;
	l->flags = w->flags;
	l->length = length_from_wire_frame_header(w);
	l->stream_identifier = stream_id_from_wire_frame_header(w);
}

void logical_to_wire_frame_header(const struct logical_frame_header* l, struct wire_frame_header* w){
	uint32_t conv;
	uint8_t* ptr;

	w->type = l->type;

	w->flags = l->flags;

	conv = htonl(l->length);
	ptr = (uint8_t*)&conv;
	w->length_arr[0] = ptr[1];
	w->length_arr[1] = ptr[2];
	w->length_arr[2] = ptr[3];

	conv = htonl(l->stream_identifier);
	ptr = (uint8_t*)&conv;
	w->stream_id_arr[0] = ptr[0];
	w->stream_id_arr[1] = ptr[1];
	w->stream_id_arr[2] = ptr[2];
	w->stream_id_arr[3] = ptr[3];
}


uint32_t stream_id_from_frame_bytes(uint8_t* frame_bytes){
		return (frame_bytes[5] & 0x7F) << 24 | frame_bytes[6] << 16 | frame_bytes[7] << 8 | frame_bytes[8];
}
uint8_t flags_from_frame_bytes(uint8_t* frame_bytes){
		return frame_bytes[4];
}
uint8_t frame_type_from_frame_bytes(uint8_t* frame_bytes){
		return frame_bytes[3];
}
char is_frame_stream_rst(uint8_t* frame_bytes, uint32_t* rst_list){
	// Possono essere anche più frame (come header + continuation), controllo solo il primo
	uint32_t fr_id = stream_id_from_frame_bytes(frame_bytes);
	if(fr_id == 0){
		return RET_FALSE;
	}
	for(int i=0; rst_list[i]!=0; i++){
		if(rst_list[i]==fr_id){
			return RET_TRUE;
		}
	}
	return RET_FALSE;
}
char is_frame_stream_opened(uint8_t* frame_bytes, uint32_t* opened_list){
	// Possono essere anche più frame (come header + continuation), controllo solo il primo
	uint32_t fr_id = stream_id_from_frame_bytes(frame_bytes);
	if(fr_id == 0){
		return RET_FALSE;
	}
	for(int i=0; opened_list[i]!=0; i++){
		if(opened_list[i]==fr_id){
			return RET_TRUE;
		}
	}
	return RET_FALSE;
}
uint32_t* add_id_to_list(uint32_t id, uint32_t* input_list){
	uint32_t* output_list;
	int t;
	for(t=0; input_list[t]!=0; t++);
	output_list = malloc(sizeof(uint32_t)*(t+2));
	for(t=0; input_list[t]!=0; t++){
		output_list[t]=input_list[t];
	}
	output_list[t] = id;
	output_list[t+1]=0;
	free(input_list);
	return output_list;
}
uint32_t* remove_id_from_list(uint32_t id, uint32_t* input_list){
	uint32_t* output_list;
	int t, i;
	for(t=0; input_list[t]!=0; t++);
	output_list = malloc(sizeof(uint32_t)*(t));
	i=0;
	for(t=0; input_list[t]!=0; t++){
		if(input_list[t]!=id){
			output_list[i++]=input_list[t];
		}
	}
	output_list[i]=0;
	free(input_list);
	return output_list;
}

void send_ipc_msg(char* socket_name, uint8_t* msg, int64_t len){
	/*
		Per evitare di rimanere bloccati con connection_error per l'invio ai socket, non garantisco
		di inviare il messaggio ma dopo MAX_IPC_SEND_ATTEMPT_COUNT tentativi scarto il messaggio
	*/
	int client_socket, t;
	struct sockaddr_un server_addr;
	long res;
	client_socket = socket(AF_UNIX, SOCK_DGRAM, 0);
	res = IPC_MSG_KERNEL_BUFFER_SIZE;
	setsockopt(client_socket, SOL_SOCKET, SO_SNDBUF, &res, sizeof(res));

	server_addr.sun_family = AF_UNIX;
	strcpy(server_addr.sun_path, socket_name);
	int attempt = 0;
	while(attempt<MAX_IPC_SEND_ATTEMPT_COUNT){
		res = sendto(client_socket, msg, len, 0, (struct sockaddr*) &server_addr, sizeof(server_addr));
		if(res != -1){
			break;
		}
		attempt++;
	}
	close(client_socket);
	return;

}

uint8_t* read_ipc_msg_nonblocking(int socket, int64_t* outlen_ptr, int additional_flags){
	// Per avere peek invece di read passare come additional_flag MSG_PEEK

	int64_t len;
	uint8_t* ptr;
	len = recv(socket, NULL, 0, MSG_DONTWAIT | MSG_PEEK);
	if(len == -1){
		if(errno != EAGAIN && errno != EWOULDBLOCK){
			perror("Errore peek read_nonblocking");
		}
		return NULL;
	}
	ioctl(socket,FIONREAD,&len);
	ptr = malloc(len);
	len = recv(socket, ptr, len, MSG_DONTWAIT | additional_flags);
	if(len==-1){
		perror("Errore recv read_nonblocking");
		return NULL;
	}
	*outlen_ptr = len;
	return ptr;
}

int16_t search_huffman_bit_string(char* bit_string){
	for(int16_t i=0; i<=255; i++){
		if(strcmp(bit_string, huffman_table[i])==0){
			return i;
		}
	}
	return -1;
}
char* append_char_to_string(char* old_str, char new_char){
	char* new_str = malloc(strlen(old_str)+2); // +2 -> 1 per il carattere, 1 per il null-terminatore
	sprintf(new_str, "%s%c", old_str, new_char);
	free(old_str);
	return new_str;
}
char index_bit_char(uint8_t* arr, uint64_t index){
	uint32_t byte_number = index/8;
	uint8_t target_byte = arr[byte_number];
	uint8_t bit_number = index%8;
	uint8_t mask = 0b10000000 >> bit_number;
	return (target_byte & mask)?'1':'0';
}
uint8_t* hpack_literal_string_to_c_string(uint8_t is_huffman_encoded, uint8_t* arr, uint32_t arr_length){
	uint32_t output_string_length = 0;
	uint8_t* output_string = NULL;
	
	if(!is_huffman_encoded){
		uint8_t* to_return = malloc(arr_length + 1);
		for(int i=0; i<arr_length; i++){
			to_return[i]=arr[i];
		}
		to_return[arr_length]=0;
		return to_return;
	}

	uint64_t total_bit_count = 8*arr_length;
	char* pending_bit_string = malloc(1);
	pending_bit_string[0]=0;
	for(uint64_t bit_index = 0; bit_index<total_bit_count; bit_index++){
		char bit_char = index_bit_char(arr, bit_index);
		pending_bit_string = append_char_to_string(pending_bit_string, bit_char);
		int16_t query_result = search_huffman_bit_string(pending_bit_string);
		if(query_result>=0){
			uint8_t* new_str = malloc(output_string_length+1);
			for(uint32_t i=0; i<output_string_length; i++){
				new_str[i]=output_string[i];
			}
			new_str[output_string_length] = query_result;
			free(output_string);
			output_string = new_str;
			output_string_length++;
			free(pending_bit_string);
			pending_bit_string = malloc(1);
			pending_bit_string[0]=0;
		}
	}
	free(pending_bit_string);

	uint8_t* to_return = malloc(output_string_length+1);
	for(uint32_t i=0; i<output_string_length; i++){
		to_return[i]=output_string[i];
	}
	to_return[output_string_length]=0;
	free(output_string);
	
	return to_return;
}

uint32_t calc_dynamic_table_header_size(uint8_t* name, uint8_t* value){
	/*
		The size of an entry is the sum of its name's length in octets (as
   		defined in Section 5.2), its value's length in octets, and 32.

		Il null-terminatore non va contato nel numero di caratteri dell'header:
		":authority" -> "www.example.com" ha dimensione 57
	*/
	if(name==NULL || value == NULL){
		printf("ERRORE: calc_dynamic_table_header_size %s %s almeno una stringa NULL\n", name, value);
		return 0;
	}
	return strlen(name)+strlen(value)+32;
}
uint32_t calc_full_dynamic_table_size(){
	uint32_t to_return = 0;
	struct dynamic_table_entry cursor = dynamic_table_head;
	while(cursor.next_entry != NULL){
		cursor = *(cursor.next_entry);
		to_return += calc_dynamic_table_header_size(cursor.header_name, cursor.header_value);
	}
	return to_return;
}
void free_dynamic_table_entry(struct dynamic_table_entry* entry){
	free(entry->header_name);
	free(entry->header_value);
	free(entry);
}
void trim_dynamic_table_for_capacity(uint32_t capacity){
	struct dynamic_table_entry* uno;
	struct dynamic_table_entry* due;
	while(capacity < calc_full_dynamic_table_size()){
		uno = &dynamic_table_head;
		due = uno -> next_entry;
		while(due->next_entry != NULL){
			uno = due;
			due = due->next_entry;
		}
		free_dynamic_table_entry(due);
		uno->next_entry = NULL;
	}
}
void update_dynamic_table_capacity(uint32_t new_capacity){
	trim_dynamic_table_for_capacity(new_capacity);
	current_dynamic_table_capacity = new_capacity;
}
void add_header_to_dynamic_table(uint8_t* header_name, uint8_t* header_value){
	/*
		Before a new entry is added to the dynamic table, entries are evicted
		from the end of the dynamic table until the size of the dynamic table
		is less than or equal to (maximum size - new entry size) or until the
		table is empty.

		If the size of the new entry is less than or equal to the maximum
		size, that entry is added to the table.  It is not an error to
		attempt to add an entry that is larger than the maximum size; an
		attempt to add an entry larger than the maximum size causes the table
		to be emptied of all existing entries and results in an empty table.
	*/
	uint32_t target_capacity = 0;
	if( calc_dynamic_table_header_size(header_name, header_value) <= current_dynamic_table_capacity ){
		target_capacity = current_dynamic_table_capacity - calc_dynamic_table_header_size(header_name, header_value);
	}
	trim_dynamic_table_for_capacity(target_capacity);

	struct dynamic_table_entry * new_entry = malloc(sizeof(struct dynamic_table_entry));
	new_entry->header_name = header_name;
	new_entry->header_value = header_value;
	new_entry->next_entry = dynamic_table_head.next_entry;
	dynamic_table_head.next_entry = new_entry;
}

// Gli indici per l'accesso alla tabella dinamica partono da 1
uint8_t* header_name_from_dynamic_table(uint32_t dynamic_table_index){
	struct dynamic_table_entry * cursor = &dynamic_table_head;
	uint32_t i=0;
	while(i<dynamic_table_index){
		cursor=cursor->next_entry;
		if(cursor == NULL){
			printf("ERRORE: index dynamic table %d non presente (# entry presenti: %d)\n", dynamic_table_index, i);
			return NULL;
		}
		i++;
	}
	return strdup(cursor->header_name);
}
uint8_t* header_value_from_dynamic_table(uint32_t dynamic_table_index){
	struct dynamic_table_entry * cursor = &dynamic_table_head;
	uint32_t i=0;
	while(i<dynamic_table_index){
		cursor=cursor->next_entry;
		if(cursor == NULL){
			printf("ERRORE: index dynamic table %d non presente (# entry presenti: %d)\n", dynamic_table_index, i);
			return NULL;
		}
		i++;
	}
	return strdup(cursor->header_value);
}


uint8_t* indexed_header_name(uint32_t index){
	if(index==0){
		printf("ERRORE Indice 0 non valido\n");
		return NULL;
	}
	if(index>61){
		return header_name_from_dynamic_table(index-61);
	}
	if(static_header_table[index-1].nome == NULL){
		return NULL;
	}
	uint8_t* to_return = malloc(strlen(static_header_table[index-1].nome)+1);
	sprintf(to_return, "%s", static_header_table[index-1].nome);
	return to_return;
}

uint8_t* indexed_header_value(uint32_t index){
	if(index==0){
		printf("ERRORE Indice 0 non valido\n");
		return NULL;
	}
	if(index>61){
		return header_value_from_dynamic_table(index-61);
	}
	if(static_header_table[index-1].valore == NULL){
		return NULL;
	}
	uint8_t* to_return = malloc(strlen(static_header_table[index-1].valore)+1);
	sprintf(to_return, "%s", static_header_table[index-1].valore);
	return to_return;
}

uint32_t decode_integer_multi_byte_encoding(uint8_t N, uint8_t* byte_arr, uint8_t arr_length){
	// N è il numero di bit (tutti 1) che erano nel primo byte dopo il padding iniziale
	/*

	https://www.rfc-editor.org/rfc/rfc7541#section-5.1

	Pseudocode to decode an integer I is as follows:

	decode I from the next N bits
	if I < 2^N - 1, return I
	else
		M = 0
		repeat
			B = next octet
			I = I + (B & 127) * 2^M
			M = M + 7
		while B & 128 == 128
		return I

	*/

	// I parte da 2^N -1
	uint32_t I = (((uint32_t)1)<<N)-1;
	
	uint8_t arr_index = 0;
	uint32_t M = 0;
	uint8_t B;
	do{
		B = byte_arr[arr_index];
		arr_index++;
		I = I + (B & 127) * ((uint32_t)1)<<M;
		M = M+7;
	}while((B & 0x80)==0x80);
	return I;
}

void free_header_list(struct header_list_node* list_head){
	while(list_head != NULL){
		if(list_head->node_header){
			free(list_head->node_header->nome);
			free(list_head->node_header->valore);
		}
		struct header_list_node* next_node = list_head->next_node;
		free(list_head->node_header);
		free(list_head);
		list_head = next_node;
	}

}

struct header_list_node* header_list_from_field_block(uint8_t* field_block_payload, const uint64_t block_length){
	uint8_t* const block_start = field_block_payload;
	struct header_list_node* const first_header_node = malloc(sizeof(struct header_list_node));
	first_header_node -> node_header = NULL;
	first_header_node -> next_node = NULL;

	struct header_list_node* node_cursor = first_header_node;

	while(field_block_payload < block_start + block_length){
		if(*field_block_payload & 0x80){
			// Pattern 1xxxxxxx
			/* Indexed Header Field Representation */
			uint8_t index = *field_block_payload & 0x7F;
			field_block_payload++;

			char* header_name = indexed_header_name(index);
			char* header_value = indexed_header_value(index);
						
			node_cursor -> node_header = malloc(sizeof(struct http_header));
			node_cursor -> node_header -> nome = header_name;
			node_cursor -> node_header -> valore = header_value;

			node_cursor -> next_node = malloc(sizeof(struct header_list_node));
			node_cursor = node_cursor->next_node;

			node_cursor->node_header = NULL;
			node_cursor->next_node = NULL;
			
			continue;
		}
		if((*field_block_payload & 0xE0) == 0b00100000){
			// Pattern 001xxxxx
			uint32_t received_max_size = *field_block_payload & 0x1F;
			field_block_payload++;

			if(received_max_size == 0x1F){
				uint8_t multi_byte_integer_length = 0;
				while((*(field_block_payload+multi_byte_integer_length))&0x80){
					multi_byte_integer_length++;
				}
				multi_byte_integer_length++; // Va contato anche il byte che inizia con 0
				uint8_t* integer_bytes_array = malloc(multi_byte_integer_length);
				for(int i=0; i<multi_byte_integer_length; i++){
					integer_bytes_array[i]=field_block_payload[i];
				}
				received_max_size = decode_integer_multi_byte_encoding(5, integer_bytes_array, multi_byte_integer_length);
				free(integer_bytes_array);
				field_block_payload+=multi_byte_integer_length;
			}
			update_dynamic_table_capacity(received_max_size);
			continue;
		}
		if((*field_block_payload & 0xC0) == 0b01000000){
			// Pattern 01xxxxxx
			/* Literal Header Field with Incremental Indexing */
			char* header_name = NULL;
			char* header_value = NULL;

			// Lettura nome
			uint32_t header_name_index = *field_block_payload & 0x3F;
			field_block_payload++;
			if(header_name_index == 0){

				uint8_t first_name_length_byte = *field_block_payload;
				field_block_payload++;

				uint8_t name_huffman_encoded = first_name_length_byte & 0x80;
				uint32_t name_length = first_name_length_byte & 0x7f;
				if(name_length==0x7F){
					uint8_t multi_byte_integer_length = 0;
					while((*(field_block_payload+multi_byte_integer_length))&0x80){
						multi_byte_integer_length++;
					}
					multi_byte_integer_length++; // Va contato anche il byte che inizia con 0
					uint8_t* integer_bytes_array = malloc(multi_byte_integer_length);
					for(int i=0; i<multi_byte_integer_length; i++){
						integer_bytes_array[i]=field_block_payload[i];
					}
					name_length = decode_integer_multi_byte_encoding(7, integer_bytes_array, multi_byte_integer_length);
					free(integer_bytes_array);
					field_block_payload+=multi_byte_integer_length;
				}
				uint8_t* name_arr = (uint8_t*) malloc(name_length);
				for(int i=0; i<name_length; i++){
					name_arr[i] = *field_block_payload;
					field_block_payload++;
				}
				header_name = hpack_literal_string_to_c_string(name_huffman_encoded, name_arr, name_length);
				free(name_arr);

			}else{
				if(header_name_index == 0x3F){
					uint8_t multi_byte_integer_length = 0;
					while((*(field_block_payload+multi_byte_integer_length))&0x80){
						multi_byte_integer_length++;
					}
					multi_byte_integer_length++; // Va contato anche il byte che inizia con 0
					uint8_t* integer_bytes_array = malloc(multi_byte_integer_length);
					for(int i=0; i<multi_byte_integer_length; i++){
						integer_bytes_array[i]=field_block_payload[i];
					}
					header_name_index = decode_integer_multi_byte_encoding(6, integer_bytes_array, multi_byte_integer_length);
					free(integer_bytes_array);
					field_block_payload+=multi_byte_integer_length;
				}
				header_name = indexed_header_name(header_name_index);
			}

			// Lettura valore
			uint8_t first_value_length_byte = *field_block_payload;
			field_block_payload++;

			uint8_t value_huffman_encoded = first_value_length_byte & 0x80;
			uint32_t value_length = first_value_length_byte & 0x7f;
			if(value_length==0x7F){
				uint8_t multi_byte_integer_length = 0;
				while((*(field_block_payload+multi_byte_integer_length))&0x80){
					multi_byte_integer_length++;
				}
				multi_byte_integer_length++; // Va contato anche il byte che inizia con 0
				uint8_t* integer_bytes_array = malloc(multi_byte_integer_length);
				for(int i=0; i<multi_byte_integer_length; i++){
					integer_bytes_array[i]=field_block_payload[i];
				}
				value_length = decode_integer_multi_byte_encoding(7, integer_bytes_array, multi_byte_integer_length);
				free(integer_bytes_array);
				field_block_payload+=multi_byte_integer_length;
			}
			uint8_t* value_arr = (uint8_t*) malloc(value_length);
			for(int i=0; i<value_length; i++){
				value_arr[i] = *field_block_payload;
				field_block_payload++;
			}
			header_value = hpack_literal_string_to_c_string(value_huffman_encoded, value_arr, value_length);
			free(value_arr);

			add_header_to_dynamic_table(strdup(header_name), strdup(header_value));


			node_cursor -> node_header = (struct http_header*) malloc(sizeof(struct http_header));
			node_cursor -> node_header -> nome = header_name;
			node_cursor -> node_header -> valore = header_value;

			node_cursor -> next_node = (struct header_list_node*) malloc(sizeof(struct header_list_node));
			node_cursor = node_cursor->next_node;

			node_cursor->node_header = NULL;
			node_cursor->next_node = NULL;

			continue;
		}
		if((*field_block_payload & 0xF0) == 0b00000000){
			// Pattern 0000xxxx
			/* Literal Header Field without Indexing */
			char* header_name = NULL;
			char* header_value = NULL;

			// Lettura nome
			uint32_t header_name_index = *field_block_payload & 0x0F;
			field_block_payload++;
			if(header_name_index == 0){

				uint8_t first_name_length_byte = *field_block_payload;
				field_block_payload++;

				uint8_t name_huffman_encoded = first_name_length_byte & 0x80;
				uint32_t name_length = first_name_length_byte & 0x7f;
				if(name_length==0x7F){
					uint8_t multi_byte_integer_length = 0;
					while((*(field_block_payload+multi_byte_integer_length))&0x80){
						multi_byte_integer_length++;
					}
					multi_byte_integer_length++; // Va contato anche il byte che inizia con 0
					uint8_t* integer_bytes_array = malloc(multi_byte_integer_length);
					for(int i=0; i<multi_byte_integer_length; i++){
						integer_bytes_array[i]=field_block_payload[i];
					}
					name_length = decode_integer_multi_byte_encoding(7, integer_bytes_array, multi_byte_integer_length);
					free(integer_bytes_array);
					field_block_payload+=multi_byte_integer_length;
				}
				uint8_t* name_arr = (uint8_t*) malloc(name_length);
				for(int i=0; i<name_length; i++){
					name_arr[i] = *field_block_payload;
					field_block_payload++;
				}
				header_name = hpack_literal_string_to_c_string(name_huffman_encoded, name_arr, name_length);
				free(name_arr);

			}else{
				if(header_name_index == 0x0F){
					uint8_t multi_byte_integer_length = 0;
					while((*(field_block_payload+multi_byte_integer_length))&0x80){
						multi_byte_integer_length++;
					}
					multi_byte_integer_length++; // Va contato anche il byte che inizia con 0
					uint8_t* integer_bytes_array = malloc(multi_byte_integer_length);
					for(int i=0; i<multi_byte_integer_length; i++){
						integer_bytes_array[i]=field_block_payload[i];
					}
					header_name_index = decode_integer_multi_byte_encoding(4, integer_bytes_array, multi_byte_integer_length);
					free(integer_bytes_array);
					field_block_payload+=multi_byte_integer_length;
				}
				header_name = indexed_header_name(header_name_index);
			}

			// Lettura valore
			uint8_t first_value_length_byte = *field_block_payload;
			field_block_payload++;

			uint8_t value_huffman_encoded = first_value_length_byte & 0x80;
			uint32_t value_length = first_value_length_byte & 0x7f;
			if(value_length==0x7F){
				uint8_t multi_byte_integer_length = 0;
				while((*(field_block_payload+multi_byte_integer_length))&0x80){
					multi_byte_integer_length++;
				}
				multi_byte_integer_length++; // Va contato anche il byte che inizia con 0
				uint8_t* integer_bytes_array = malloc(multi_byte_integer_length);
				for(int i=0; i<multi_byte_integer_length; i++){
					integer_bytes_array[i]=field_block_payload[i];
				}
				value_length = decode_integer_multi_byte_encoding(7, integer_bytes_array, multi_byte_integer_length);
				free(integer_bytes_array);
				field_block_payload+=multi_byte_integer_length;
			}
			uint8_t* value_arr = (uint8_t*) malloc(value_length);
			for(int i=0; i<value_length; i++){
				value_arr[i] = *field_block_payload;
				field_block_payload++;
			}
			header_value = hpack_literal_string_to_c_string(value_huffman_encoded, value_arr, value_length);
			free(value_arr);

			node_cursor -> node_header = (struct http_header*) malloc(sizeof(struct http_header));
			node_cursor -> node_header -> nome = header_name;
			node_cursor -> node_header -> valore = header_value;

			node_cursor -> next_node = (struct header_list_node*) malloc(sizeof(struct header_list_node));
			node_cursor = node_cursor->next_node;

			node_cursor->node_header = NULL;
			node_cursor->next_node = NULL;

			continue;
		}
		if((*field_block_payload & 0xF0) == 0b00010000){
			// Pattern 0001xxxx
			/* Literal Header Field Never Indexed */
			char* header_name = NULL;
			char* header_value = NULL;

			// Lettura nome
			uint32_t header_name_index = *field_block_payload & 0x0F;
			field_block_payload++;
			if(header_name_index == 0){

				uint8_t first_name_length_byte = *field_block_payload;
				field_block_payload++;

				uint8_t name_huffman_encoded = first_name_length_byte & 0x80;
				uint32_t name_length = first_name_length_byte & 0x7f;
				if(name_length==0x7F){
					uint8_t multi_byte_integer_length = 0;
					while((*(field_block_payload+multi_byte_integer_length))&0x80){
						multi_byte_integer_length++;
					}
					multi_byte_integer_length++; // Va contato anche il byte che inizia con 0
					uint8_t* integer_bytes_array = malloc(multi_byte_integer_length);
					for(int i=0; i<multi_byte_integer_length; i++){
						integer_bytes_array[i]=field_block_payload[i];
					}
					name_length = decode_integer_multi_byte_encoding(7, integer_bytes_array, multi_byte_integer_length);
					free(integer_bytes_array);
					field_block_payload+=multi_byte_integer_length;
				}
				uint8_t* name_arr = (uint8_t*) malloc(name_length);
				for(int i=0; i<name_length; i++){
					name_arr[i] = *field_block_payload;
					field_block_payload++;
				}
				header_name = hpack_literal_string_to_c_string(name_huffman_encoded, name_arr, name_length);
				free(name_arr);

			}else{
				if(header_name_index == 0x0F){
					uint8_t multi_byte_integer_length = 0;
					while((*(field_block_payload+multi_byte_integer_length))&0x80){
						multi_byte_integer_length++;
					}
					multi_byte_integer_length++; // Va contato anche il byte che inizia con 0
					uint8_t* integer_bytes_array = malloc(multi_byte_integer_length);
					for(int i=0; i<multi_byte_integer_length; i++){
						integer_bytes_array[i]=field_block_payload[i];
					}
					header_name_index = decode_integer_multi_byte_encoding(4, integer_bytes_array, multi_byte_integer_length);
					free(integer_bytes_array);
					field_block_payload+=multi_byte_integer_length;
				}
				header_name = indexed_header_name(header_name_index);
			}

			// Lettura valore
			uint8_t first_value_length_byte = *field_block_payload;
			field_block_payload++;

			uint8_t value_huffman_encoded = first_value_length_byte & 0x80;
			uint32_t value_length = first_value_length_byte & 0x7f;
			if(value_length==0x7F){
				uint8_t multi_byte_integer_length = 0;
				while((*(field_block_payload+multi_byte_integer_length))&0x80){
					multi_byte_integer_length++;
				}
				multi_byte_integer_length++; // Va contato anche il byte che inizia con 0
				uint8_t* integer_bytes_array = malloc(multi_byte_integer_length);
				for(int i=0; i<multi_byte_integer_length; i++){
					integer_bytes_array[i]=field_block_payload[i];
				}
				value_length = decode_integer_multi_byte_encoding(7, integer_bytes_array, multi_byte_integer_length);
				free(integer_bytes_array);
				field_block_payload+=multi_byte_integer_length;
			}
			uint8_t* value_arr = (uint8_t*) malloc(value_length);
			for(int i=0; i<value_length; i++){
				value_arr[i] = *field_block_payload;
				field_block_payload++;
			}
			header_value = hpack_literal_string_to_c_string(value_huffman_encoded, value_arr, value_length);
			free(value_arr);

			node_cursor -> node_header = (struct http_header*) malloc(sizeof(struct http_header));
			node_cursor -> node_header -> nome = header_name;
			node_cursor -> node_header -> valore = header_value;

			node_cursor -> next_node = (struct header_list_node*) malloc(sizeof(struct header_list_node));
			node_cursor = node_cursor->next_node;

			node_cursor->node_header = NULL;
			node_cursor->next_node = NULL;

			continue;
		}

		printf("Tipo header non gestito: %x\n", *field_block_payload);
		break;
	}
	return first_header_node;
}


uint8_t* make_400_response(uint32_t stream_identifier, int64_t* outlen){
	// Lo metto qui invece che nei #define così se cambio qualcosa in come creo la 500 cambio tutto qui dentro
	const uint32_t RESPONSE_400_BYTE_LENGTH = 10;

	uint8_t* to_return = malloc(RESPONSE_400_BYTE_LENGTH);
	*outlen = RESPONSE_400_BYTE_LENGTH;

	// Lunghezza payload: 1 byte (solo 1 header)
	to_return[0]=0x00;
	to_return[1]=0x00;
	to_return[2]=0x01;

	// Tipo: 0x01 (HEADERS)
	to_return[3]=FRAME_TYPE_HEADERS;

	// Flags: 0x05 (Priority 0, Padded 0, End headers 1, End stream 1)
	to_return[4]= 0x00 | FLAG_END_HEADERS | FLAG_END_STREAM;

	// Stream identifier: uguale a quello passato come parametro (byte 5,6,7,8)
	to_return[5]=(stream_identifier>>24)&0xFF;
	to_return[6]=(stream_identifier>>16)&0xFF;
	to_return[7]=(stream_identifier>>8)&0xFF;
	to_return[8]=(stream_identifier)&0xFF;

	// Payload: 0x8B (primo bit a 1: sia nome che valore indicizzati, ultimi 7 byte = 12 in binario -> :status 400)
	to_return[9]=0x8C;

	return to_return;
}
uint8_t* make_404_response(uint32_t stream_identifier, int64_t* outlen){
	// Lo metto qui invece che nei #define così se cambio qualcosa in come creo la 404 cambio tutto qui dentro
	const uint32_t RESPONSE_404_BYTE_LENGTH = 10;

	uint8_t* to_return = malloc(RESPONSE_404_BYTE_LENGTH);
	*outlen = RESPONSE_404_BYTE_LENGTH; 

	// Lunghezza payload: 1 byte (solo 1 header)
	to_return[1]=0x00;
	to_return[0]=0x00;
	to_return[2]=0x01;

	// Tipo: 0x01 (HEADERS)
	to_return[3]=FRAME_TYPE_HEADERS;

	// Flags: 0x05 (Priority 0, Padded 0, End headers 1, End stream 1)
	to_return[4]= 0x00 | FLAG_END_HEADERS | FLAG_END_STREAM;

	// Stream identifier: uguale a quello passato come parametro (byte 5,6,7,8)
	to_return[5]=(stream_identifier>>24)&0xFF;
	to_return[6]=(stream_identifier>>16)&0xFF;
	to_return[7]=(stream_identifier>>8)&0xFF;
	to_return[8]=(stream_identifier)&0xFF;

	// Payload: 0x8D (primo bit a 1: sia nome che valore indicizzati, ultimi 7 byte = 13 in binario -> :status 404)
	to_return[9]=0x8D;

	return to_return;
}
uint8_t* make_200_response_headers(uint32_t stream_identifier, int64_t* outlen){
	const uint32_t RESPONSE_200_HEADER_BYTE_LENGTH = 10;

	uint8_t* to_return = malloc(RESPONSE_200_HEADER_BYTE_LENGTH);
	*outlen = RESPONSE_200_HEADER_BYTE_LENGTH;

	// Lunghezza payload: 1 byte (solo 1 header)
	to_return[0]=0x00;
	to_return[1]=0x00;
	to_return[2]=0x01;

	// Tipo: 0x01 (HEADERS)
	to_return[3]=FRAME_TYPE_HEADERS;

	// Flags: 0x05 (Priority 0, Padded 0, End headers 1, End stream 1)
	to_return[4]= FLAG_END_HEADERS;

	// Stream identifier: uguale a quello passato come parametro (byte 5,6,7,8)
	to_return[5]=(stream_identifier>>24)&0x7F;
	to_return[6]=(stream_identifier>>16)&0xFF;
	to_return[7]=(stream_identifier>>8)&0xFF;
	to_return[8]=(stream_identifier)&0xFF;

	// Payload: 0x88 (primo bit a 1: sia nome che valore indicizzati, ultimi 7 byte = 8 in binario -> :status 200)
	to_return[9]=0x88;

	return to_return;
}
uint8_t* make_push_promise(uint32_t stream_identifier, int64_t* outlen, uint32_t new_stream_id, char* pushed_resource){
	/*
		Frame PUSH_PROMISE: 9 byte iniziali + 4 byte nuovo stream id + field block
		Gli headers vengono codificati come Literal Header Field without Indexing,
		sia nome che valore sono codificati come literal, non viene codificato niente 
		con Huffman.
	*/
	struct http_header* request_header_list;
	int request_header_list_size, number_of_chars, field_block_length, i, j;
	uint8_t* to_return;
	uint8_t* payload_cursor;
	uint32_t payload_length;

	request_header_list_size = 4;
	request_header_list = malloc(request_header_list_size * sizeof(struct http_header));
	request_header_list[0].nome = strdup(":method");
	request_header_list[0].valore = strdup("GET");

	request_header_list[1].nome = strdup(":path");
	request_header_list[1].valore = strdup(pushed_resource);

	request_header_list[2].nome = strdup(":scheme");
	request_header_list[2].valore = strdup("https");

	request_header_list[3].nome = strdup(":authority");
	request_header_list[3].valore = strdup(SERVER_AUTHORITY);

	number_of_chars = 0;
	for(int i=0; i<request_header_list_size; i++){
		number_of_chars += strlen(request_header_list[i].nome)+strlen(request_header_list[i].valore);
	}
	field_block_length = 3*request_header_list_size+number_of_chars;
	payload_length = 4+field_block_length;
	*outlen = 9+payload_length;
	to_return=malloc(*outlen);

	to_return[0]=(payload_length>>16)&0xFF;
	to_return[1]=(payload_length>>8)&0xFF;
	to_return[2]=payload_length&0xFF;

	to_return[3]=FRAME_TYPE_PUSH_PROMISE;

	to_return[4]=FLAG_END_HEADERS;

	to_return[5]=(stream_identifier>>24)&0x7F;
	to_return[6]=(stream_identifier>>16)&0xFF;
	to_return[7]=(stream_identifier>>8)&0xFF;
	to_return[8]=stream_identifier&0xFF;

	to_return[9]=(new_stream_id>>24)&0x7F;
	to_return[10]=(new_stream_id>>16)&0xFF;
	to_return[11]=(new_stream_id>>8)&0xFF;
	to_return[12]=new_stream_id&0xFF;

	payload_cursor = to_return+13;
	for(i=0; i<request_header_list_size; i++){
		/*
			Struttura del singolo header:
			1 byte 0x00 (Literal Header Field without Indexing -- New Name)
			1 byte lunghezza nome
			... byte nome
			1 byte lunghezza valore
			... byte valore
		*/
		*payload_cursor++ = 0;
		*payload_cursor++ = strlen(request_header_list[i].nome);
		for(j=0; j<strlen(request_header_list[i].nome); j++){
			*payload_cursor++ = request_header_list[i].nome[j];
		}
		*payload_cursor++ = strlen(request_header_list[i].valore);
		for(j=0; j<strlen(request_header_list[i].valore); j++){
			*payload_cursor++ = request_header_list[i].valore[j];
		}
	}

	for(i=0; i<request_header_list_size; i++){
		free(request_header_list[i].nome);
		free(request_header_list[i].valore);
	}

	free(request_header_list);

	return to_return;
}

uint8_t* read_data_chunk(int fd, uint32_t* outlen, char* out_is_last_chunk){
	int len, t;
	uint32_t target_data_frame_length = DATA_FRAME_PAYLOAD_SIZE<client_max_frame_size?DATA_FRAME_PAYLOAD_SIZE:client_max_frame_size;
	uint8_t* to_return = malloc(target_data_frame_length);
	if(!FORCE_FULL_DATA_FRAME){
		len = read(fd, to_return, target_data_frame_length);
		*out_is_last_chunk = (len == 0);
		*outlen = len;
	}else{
		len = 0;
		*out_is_last_chunk = 0;
		while(len < target_data_frame_length){
			t = read(fd, to_return+len, target_data_frame_length);
			if(t<=0){
				*out_is_last_chunk = 1;
				break;
			}
			len += t;
		}
		*outlen = len;
	}
	return to_return;
}
uint8_t* make_data_frame(uint32_t stream_identifier, int64_t* outlen, int fd, char* out_is_last_frame){
	const uint32_t DATA_FRAME_HEADER_LENGTH = 9;
	uint8_t* to_return;
	uint32_t chunk_length;
	uint8_t* chunk_data;
	char is_last_chunk;
	chunk_data = read_data_chunk(fd, &chunk_length, &is_last_chunk);
	to_return = malloc(DATA_FRAME_HEADER_LENGTH + chunk_length);
	*outlen = DATA_FRAME_HEADER_LENGTH + chunk_length;
	*out_is_last_frame = is_last_chunk;

	to_return[0]=(chunk_length>>16)&0xFF;
	to_return[1]=(chunk_length>>8)&0xFF;
	to_return[2]=(chunk_length)&0xFF;

	to_return[3]=FRAME_TYPE_DATA;

	to_return[4]=is_last_chunk?FLAG_END_STREAM:0x00;

	// Stream identifier: uguale a quello passato come parametro (byte 5,6,7,8)
	to_return[5]=(stream_identifier>>24)&0xFF;
	to_return[6]=(stream_identifier>>16)&0xFF;
	to_return[7]=(stream_identifier>>8)&0xFF;
	to_return[8]=(stream_identifier)&0xFF;

	// Payload
	memcpy(to_return+DATA_FRAME_HEADER_LENGTH, chunk_data, chunk_length);
	free(chunk_data);
	return to_return;
}
uint32_t obtain_new_stream_id(){
	/*
		Per evitare di rimanere bloccati con connection_error per l'invio ai socket, non garantisco
		di inviare il messaggio ma dopo MAX_IPC_SEND_ATTEMPT_COUNT tentativi scarto il messaggio
	*/
	int s_to, s_from, t;
	struct sockaddr_un recv_addr, send_mgr_addr;
	long res;
	char* command_socket_file_path;
	char* msg;
	char* recv_sock_name;
	char* ptr;
	uint32_t to_return;

	res = IPC_MSG_KERNEL_BUFFER_SIZE;
	asprintf(&recv_sock_name, NEW_STREAM_SOCKET_PATH_TEMPLATE, getpid());
	asprintf(&command_socket_file_path, COMMAND_SOCKET_PATH_TEMPLATE, connection_socket_identifier);
	asprintf(&msg, NEW_STREAM_ID_CMD_TEMPLATE, recv_sock_name);


	s_from = socket(AF_UNIX, SOCK_DGRAM, 0);
	setsockopt(s_from, SOL_SOCKET, SO_RCVBUF, &res, sizeof(res));
	recv_addr.sun_family = AF_UNIX;
	strcpy(recv_addr.sun_path, recv_sock_name);
	t = sizeof(recv_addr);
	unlink(recv_addr.sun_path);
	bind(s_from, (struct sockaddr*)&recv_addr, t);

	s_to = socket(AF_UNIX, SOCK_DGRAM, 0);
	setsockopt(s_to, SOL_SOCKET, SO_SNDBUF, &res, sizeof(res));

	send_mgr_addr.sun_family = AF_UNIX;
	strcpy(send_mgr_addr.sun_path, command_socket_file_path);

	while(1){
		res = sendto(s_to, msg, strlen(msg)+1 /*+1 per il '\0' alla fine della stringa*/, 0, (struct sockaddr*) &send_mgr_addr, sizeof(send_mgr_addr));
		if(res != -1){
			break;
		}
	}
	do{
		ptr = read_ipc_msg_nonblocking(s_from, &res, 0);
	}while(ptr==NULL);
	to_return = atoi(ptr);

	close(s_to);
	close(s_from);
	unlink(recv_sock_name);

	free(command_socket_file_path);
	free(recv_sock_name);
	free(msg);

	return to_return; 
}
void send_response(int32_t request_stream_identifier, struct header_list_node* const header_list_first_node){
	if(fork()){
		return;
	}
	uint8_t* response_headers_bytes;
	int64_t response_headers_length;
	char has_body;
	int write_result;
	
	struct header_list_node* node_cursor = header_list_first_node;
	
	char* request_path = NULL;
	while(node_cursor != NULL){
		if(node_cursor -> node_header != NULL && node_cursor -> node_header -> nome != NULL){
			if(!strcmp(node_cursor -> node_header -> nome, ":path")){
				request_path = node_cursor -> node_header -> valore;
			}
		}
		node_cursor = node_cursor -> next_node;
	}
	if(request_path	== NULL || request_path[0]!='/'){
		printf("Percorso %s non valido: response 400\n", request_path);
		response_headers_bytes = make_400_response(request_stream_identifier, &response_headers_length);
		has_body = 0;
		goto invio_risposta;
	}
	char* file_path_from_root = request_path +1; // Tolgo il '/' iniziale
	if(strlen(file_path_from_root)==0){
		// Ho chiesto "/", rispondo con il file della homepage (index.html)
		file_path_from_root = HOMEPAGE_FILENAME;
	}

	char* full_file_path = malloc(strlen(WEBSITE_ROOT_DIRECTORY) + strlen(file_path_from_root) + 1); // il +1 è per lo zero finale
	sprintf(full_file_path, "%s%s", WEBSITE_ROOT_DIRECTORY, file_path_from_root);

	int fd = open(full_file_path, O_RDONLY);
	if(fd<=0){
		printf("File %s non trovato: response 404\n", full_file_path);
		response_headers_bytes = make_404_response(request_stream_identifier, &response_headers_length);
		has_body = 0;
	}else{
		printf("File trovato\n");
		response_headers_bytes = make_200_response_headers(request_stream_identifier, &response_headers_length);
		has_body = 1;
	}



	invio_risposta:
	// https://stackoverflow.com/a/3774505
	char* headers_socket_file_path;
	asprintf(&headers_socket_file_path, HEADERS_SOCKET_PATH_TEMPLATE, connection_socket_identifier);
	send_ipc_msg(headers_socket_file_path, response_headers_bytes, response_headers_length);
	free(headers_socket_file_path);

	printf("Response headers inviati a send_manager\n");
	free(response_headers_bytes);

	
	if(has_body && USE_PUSH_IF_ENABLED && push_enabled){
		printf("Carico file risorse push\n");
		char* push_list_full_file_path;
		asprintf(&push_list_full_file_path, "%s%s%s", WEBSITE_ROOT_DIRECTORY, file_path_from_root, PUSH_LIST_FILE_SUFFIX);
		printf("push_list_full_file_path %s\n", push_list_full_file_path);
		FILE* file_push_list = fopen(push_list_full_file_path, "r");
		free(push_list_full_file_path);
		if(file_push_list == NULL){
			printf("file_push_list non trovato\n");
			goto invio_body;
		}
		char line[PUSH_FILE_LINE_BUFFER_SIZE];
		while (fgets(line, PUSH_FILE_LINE_BUFFER_SIZE, file_push_list) != NULL) {
			if(strstr(line, "\n")){
				line[strcspn(line, "\n")] = '\0';
			}
			if(strstr(line, "\r")){
				line[strcspn(line, "\r")] = '\0';
			}
			char* relative_push_res_path;
			asprintf(&relative_push_res_path, "/%s", line);
			char* full_push_res_path;
			asprintf(&full_push_res_path, "%s%s", WEBSITE_ROOT_DIRECTORY, line);

			int fd_push = open(full_push_res_path, O_RDONLY);
			if(fd_push>0){
				char* sock_file_path;
				uint32_t new_stream_id = obtain_new_stream_id();
				int64_t push_promise_length;
				uint8_t* push_promise_bytes = make_push_promise(request_stream_identifier, &push_promise_length, new_stream_id, relative_push_res_path);
				
				asprintf(&headers_socket_file_path, HEADERS_SOCKET_PATH_TEMPLATE, connection_socket_identifier);
				send_ipc_msg(headers_socket_file_path, push_promise_bytes, push_promise_length);
				free(headers_socket_file_path);

				printf("Inviato frame PUSH_PROMISE per risorsa %s sullo stream %d (nuovo stream_id: %d)\n", relative_push_res_path,request_stream_identifier, new_stream_id);

				free(push_promise_bytes);

				response_headers_bytes = make_200_response_headers(new_stream_id, &response_headers_length);

				asprintf(&headers_socket_file_path, HEADERS_SOCKET_PATH_TEMPLATE, connection_socket_identifier);
				send_ipc_msg(headers_socket_file_path, response_headers_bytes, response_headers_length);
				free(headers_socket_file_path);

				printf("Inviato frame HEADERS per risorsa push %s sullo stream %d\n", relative_push_res_path,new_stream_id);


				free(response_headers_bytes);

				if(!fork()){
					int64_t data_frame_length;
					uint8_t* data_frame;
					char is_last_frame;
					char* data_socket_file_path;
					asprintf(&data_socket_file_path, DATA_SOCKET_PATH_TEMPLATE, connection_socket_identifier);
					do{
						data_frame = make_data_frame(new_stream_id, &data_frame_length, fd_push, &is_last_frame);
						send_ipc_msg(data_socket_file_path, data_frame, data_frame_length);
						free(data_frame);
					}while(!is_last_frame);
					printf("Inviati frame DATA per il push risorsa %s sullo stream %d\n", relative_push_res_path, new_stream_id);
					free(data_socket_file_path);
					close(fd_push);
					exit(0);
				}
			}
			free(relative_push_res_path);
			free(full_push_res_path);
		}
		
		fclose(file_push_list);

	}

	invio_body:
	if(has_body){
		int64_t data_frame_length;
		uint8_t* data_frame;
		char is_last_frame;
		char* data_socket_file_path;
		asprintf(&data_socket_file_path, DATA_SOCKET_PATH_TEMPLATE, connection_socket_identifier);
		do{
			data_frame = make_data_frame(request_stream_identifier, &data_frame_length, fd, &is_last_frame);
			send_ipc_msg(data_socket_file_path, data_frame, data_frame_length);
			free(data_frame);
		}while(!is_last_frame);
		free(data_socket_file_path);
		close(fd);
		printf("Data frame inviati a send_manager sullo stream %d\n", request_stream_identifier);
	}
	exit(0);
}

uint8_t read_bytes_nonblocking(SSL* ssl, uint8_t* in_buffer, int in_buffer_size, int in_buffer_capacity, uint8_t** out_buffer, int* out_buffer_size, int* out_buffer_capacity){
	uint8_t* current_buffer = in_buffer;
	int current_buffer_size = in_buffer_size;
	int current_buffer_capacity = in_buffer_capacity;

	int read_ret_val;

	uint8_t one_read_completed = 0;

	do{
		if(current_buffer_size >= current_buffer_capacity){
			current_buffer_capacity *= 2;
			uint8_t* new_buffer = malloc(current_buffer_capacity);
			memcpy(new_buffer, current_buffer, current_buffer_size);
			free(current_buffer);
			current_buffer = new_buffer;
		}
		read_ret_val = SSL_read(ssl, current_buffer+current_buffer_size, current_buffer_capacity-current_buffer_size);
		if(read_ret_val>0){
			current_buffer_size += read_ret_val;
			one_read_completed = 1;
		}
	}while(read_ret_val >0);

	*out_buffer = current_buffer;
	*out_buffer_size = current_buffer_size;
	*out_buffer_capacity = current_buffer_capacity;

	if(!one_read_completed){
		switch(SSL_get_error(ssl, read_ret_val)){
			case SSL_ERROR_WANT_READ:
				return READ_RESULT_NOTHING;
			case SSL_ERROR_WANT_WRITE:
				return READ_RESULT_NOTHING;
			default:
				return READ_RESULT_ERROR;
		}
	}

	return READ_RESULT_OK;
}
struct full_frame_list_node* extract_frames_from_buffer(uint8_t* in_buffer, int in_buffer_size, int in_buffer_capacity, uint8_t** out_buffer, int* out_buffer_size, int* out_buffer_capacity){
	uint8_t* current_buffer = in_buffer;
	int current_buffer_size = in_buffer_size;
	int current_buffer_capacity = in_buffer_capacity;

	int byte_consumati = 0;
	int total_headers_number = 0;

	struct full_frame_list_node* to_return = NULL;

	if(current_buffer_size<9){
		goto end_parsing;
	}

	uint32_t first_frame_length = current_buffer[0]<<16 | current_buffer[1]<<8 | current_buffer[2];

	if(current_buffer_size<9+first_frame_length){
		goto end_parsing;
	}

	uint8_t first_frame_type = current_buffer[3];
	uint8_t first_frame_flags = current_buffer[4];

	total_headers_number = 1;
	if((first_frame_type == FRAME_TYPE_HEADERS) && !(first_frame_flags & FLAG_END_HEADERS)){
		int inizio_corrente = 0;
		while(1){
			if(inizio_corrente + 9 > current_buffer_size){
				break;
			}
			if(current_buffer[inizio_corrente+4] & FLAG_END_HEADERS){
				break;
			}
			inizio_corrente+= (9+(current_buffer[inizio_corrente+0]<<16 | current_buffer[inizio_corrente+1]<<8 | current_buffer[inizio_corrente+2]));
			total_headers_number++;
		}
		if(inizio_corrente + 9 > current_buffer_size){
			goto end_parsing;
		}
		if(!((current_buffer[inizio_corrente +4]&FLAG_END_HEADERS) && ( (inizio_corrente + 9 + (current_buffer[inizio_corrente+0]<<16 | current_buffer[inizio_corrente+1]<<8 | current_buffer[inizio_corrente+2])) <= current_buffer_size))){
			// Non ho frame interi con flag END_HEADERS
			goto end_parsing;
		}
	}
	struct full_frame_list_node** previous_ptr = &to_return;
	int inizio_frame = 0;
	for(int i=0; i<total_headers_number; i++){
		struct full_frame_list_node* new_node = malloc(sizeof(struct full_frame_list_node));

		*previous_ptr = new_node;
		new_node->next = NULL;
		previous_ptr = &(new_node->next);

		uint32_t f_length = current_buffer[inizio_frame+0]<<16 | current_buffer[inizio_frame+1]<<8 | current_buffer[inizio_frame+2];
		uint8_t f_type = current_buffer[inizio_frame+3];
		uint8_t f_flags = current_buffer[inizio_frame+4];
		uint32_t f_stream = current_buffer[inizio_frame+5]<<24 | current_buffer[inizio_frame+6]<<16 | current_buffer[inizio_frame+7]<<8 | current_buffer[inizio_frame+8];
				
		new_node->frame.header.length = f_length;
		new_node->frame.header.type = f_type;
		new_node->frame.header.flags = f_flags;
		new_node->frame.header.stream_identifier = f_stream;
		new_node->frame.payload = malloc(f_length);
		memcpy(new_node->frame.payload, current_buffer+inizio_frame+9, f_length);

		
		inizio_frame+= (9+f_length);
	}

	byte_consumati = inizio_frame;

	
	end_parsing:
	if(byte_consumati>0){
		int remaining_bytes = current_buffer_size - byte_consumati;
		// Sorgente e destinazione si sovrappongono quindi devo usare memmove
		memmove(current_buffer, current_buffer+byte_consumati, remaining_bytes);
		current_buffer_size = remaining_bytes;
	}
	int treshold = current_buffer_capacity/3;
	if(current_buffer_size < treshold){
		current_buffer_capacity = MIN_H2_READ_BYTE_BUFFER_CAPACITY>treshold?MIN_H2_READ_BYTE_BUFFER_CAPACITY:treshold;
		uint8_t* new_buffer = malloc(current_buffer_capacity);
		memcpy(new_buffer, current_buffer, current_buffer_size);
		free(current_buffer);
		current_buffer = new_buffer;
	}
	*out_buffer = current_buffer;
	*out_buffer_size = current_buffer_size;
	*out_buffer_capacity = current_buffer_capacity;
	return to_return;
}

void handle_settings_frame(SSL* ssl, struct full_frame_list_node* frame_list, int32_t* const current_initial_window_size_ptr, int32_t* const current_connection_window_size_ptr){
	const struct logical_frame_wire_payload* rec = &(frame_list->frame);
	if(rec->header.stream_identifier != 0){
		printf("ERRORE NON GESTITO: ricevuto settings con stream != 0\n");
		return;
	}
	int i, rec_payload_len = rec->header.length;
	struct wire_setting* wire_ptr;
	struct logical_setting s;
	if(rec_payload_len % sizeof(struct wire_setting)){
		printf("WARNING: ricevuto frame settings con length non multiplo di sizeof(setting)\n");
		printf("rec_payload_len=%d, sizeof(setting)=%lu\n", rec_payload_len, sizeof(struct wire_setting));
	}
	int num_settings = rec_payload_len / sizeof(struct wire_setting);
	printf("Ricevuti %d setting\n", num_settings);
	if(rec->header.flags & FLAG_ACK){
		printf("Frame SETTINGS ack\n");
		if(rec->header.length != 0){
			printf("ERRORE NON GESTITO: Ricevuto ack settings con lunghezza != 0\n");
		}
		server_settings_ack_received = 1;
		return;
	}else{
		client_settings_frame_received = 1;
	}
	printf("Lettura settings...\n");
	for(i=0; i<num_settings; i++){
		wire_ptr = (struct wire_setting*) (rec->payload + i*sizeof(struct wire_setting));
		wire_to_logical_setting(wire_ptr, &s);
		printf("Setting #%d: id=%d value=%d\n", i, s.id, s.value);
		switch(s.id){
			case SETTINGS_HEADER_TABLE_SIZE:
				printf("SETTINGS_HEADER_TABLE_SIZE %u\n", s.value);
				client_header_table_size = s.value;
				break;
			case SETTINGS_ENABLE_PUSH:
				printf("SETTINGS_ENABLE_PUSH %u\n", s.value);
				switch(s.value){
					case 0:
						push_enabled = 0;
						break;
					case 1:
						push_enabled = 1;
						break;
					default:
						printf("ERRORE NON GESTITO: Ricevuto SETTINGS_ENABLE_PUSH non valido\n");
				}
				break; 
			case SETTINGS_MAX_CONCURRENT_STREAMS:
				printf("SETTINGS_MAX_CONCURRENT_STREAMS %u\n", s.value);
				client_max_concurrent_streams = s.value;
				break; 
			case SETTINGS_INITIAL_WINDOW_SIZE:
				printf("SETTINGS_INITIAL_WINDOW_SIZE %u\n", s.value);
				if(s.value <= 2147483647){
					int32_t offset = *current_connection_window_size_ptr - *current_initial_window_size_ptr;
					*current_initial_window_size_ptr = s.value;
					*current_connection_window_size_ptr = s.value + offset;
				}else{
					printf("ERRORE NON GESTITO: Ricevuto SETTINGS_INITIAL_WINDOW_SIZE non valido\n");
				}
				break; 
			case SETTINGS_MAX_FRAME_SIZE:
				printf("SETTINGS_MAX_FRAME_SIZE %u\n", s.value);
				if(s.value <= 16777215){
					client_max_frame_size = s.value;
				}else{
					printf("ERRORE NON GESTITO: Ricevuto SETTINGS_MAX_FRAME_SIZE non valido\n");
				}
				break; 
			case SETTINGS_MAX_HEADER_LIST_SIZE:
				printf("SETTINGS_MAX_HEADER_LIST_SIZE %u\n", s.value);
				client_max_header_list_size_specified = 1;
				client_max_header_list_size = s.value;
				break;
			default:
				printf("Setting id sconosciuto (ignorato)\n");
		}
	}

	// Invio SETTINGS ACK
	uint8_t r[9]; //response: 9 byte header
	// Length (0x08)
	r[0]=0;
	r[1]=0;
	r[2]=0;

	// Type
	r[3]=FRAME_TYPE_SETTINGS;

	// Flags
	r[4]=FLAG_ACK;

	// Stream identifier (0x00)
	r[5]=0;
	r[6]=0;
	r[7]=0;
	r[8]=0;

	char* urgent_socket_file_path;
	asprintf(&urgent_socket_file_path, URGENT_SOCKET_PATH_TEMPLATE, connection_socket_identifier);
	send_ipc_msg(urgent_socket_file_path, r, 9);
	free(urgent_socket_file_path);
	
	printf("SETTINGS ACK inviato a send_manager\n");
}

void handle_ping_frame(SSL* ssl, struct full_frame_list_node* frame_list){
	const struct logical_frame_wire_payload* rec = &(frame_list->frame);
	uint8_t b; // usato per ack e scrittura response
	uint8_t i;
	uint8_t r[17]; //response: 9 byte header + 8 byte payload
	if(rec->header.stream_identifier != 0){
		printf("ERRORE NON GESTITO: ricevuto ping con stream != 0\n");
		return;
	}
	if(rec->header.length != 8){
		printf("ERRORE NON GESTITO: ricevuto ping con length != 8\n");
		return;
	}
	b = rec->header.flags & FLAG_ACK;
	if(b){
		printf("Ricevuto ping ACK\n");
		// Non faccio controlli sul payload (non ho intenzione di inviare nessun ping, quindi non ho nessun controllo da fare)
		return;
	}

	printf("Opaque payload: 0x");
	for(i=0; i<rec->header.length; i++){
		printf("%02x", rec->payload[i]);
	}
	printf("\n");


	// Length (0x08)
	r[0]=0;
	r[1]=0;
	r[2]=8;

	// Type
	r[3]=FRAME_TYPE_PING;

	// Flags
	r[4]=FLAG_ACK;

	// Stream identifier (0x00)
	r[5]=0;
	r[6]=0;
	r[7]=0;
	r[8]=0;

	// Opaque data
	for(i=0; i<8; i++){
		r[9+i] = rec->payload[i];
	}

	char* urgent_socket_file_path;
	asprintf(&urgent_socket_file_path, URGENT_SOCKET_PATH_TEMPLATE, connection_socket_identifier);
	send_ipc_msg(urgent_socket_file_path, r, 17);
	free(urgent_socket_file_path);
	
	printf("PING ACK inviato a send_manager\n");
	return;
}

void handle_goaway_frame(SSL* ssl, struct full_frame_list_node* frame_list){
	const struct logical_frame_wire_payload* rec = &(frame_list->frame);
	printf("------------\n");
	printf("GOAWAY\n");

	printf("length: %d\n", rec->header.length);
	printf("stream_identifier: %d\n", rec->header.stream_identifier);

	printf("HEX GOAWAY PAYLOAD CONTENT:\n");
	for(int i=0; i<rec->header.length; i++){
		printf("%02x", rec->payload[i]);
	}
	printf("\n");
	uint32_t last_stream_id = rec->payload[0]<<24|rec->payload[1]<<16|rec->payload[2]<<8|rec->payload[3];
	printf("Last-Stream-ID: %u\n", last_stream_id);
	uint32_t error_code = rec->payload[4]<<24|rec->payload[5]<<16|rec->payload[6]<<8|rec->payload[7];
	printf("Error Code: %u\n", error_code);
	printf("Error description: %s\n", error_description_from_code(error_code));
	printf("Additional Debug Data: |");
	for(int i=8; i<rec->header.length; i++){
		printf("%c", rec->payload[i]);
	}
	printf("|\n");
	printf("------------\n");
}

void handle_headers_frame(SSL* ssl, struct full_frame_list_node* frame_list){
	const struct logical_frame_wire_payload* rec = &(frame_list->frame);
	uint32_t request_stream_identifier = rec->header.stream_identifier;

	uint8_t priority_flag = rec->header.flags & FLAG_PRIORITY;
	uint8_t padded_flag = rec->header.flags & FLAG_PADDED;
	uint8_t end_headers_flag = rec->header.flags & FLAG_END_HEADERS;
	uint8_t end_stream_flag = rec->header.flags & FLAG_END_STREAM;

	printf("HEADERS frame flags: ");
	if(priority_flag){
		printf("PRIORITY ");
	}
	if(padded_flag){
		printf("PADDED ");
	}
	if(end_headers_flag){
		printf("END_HEADERS ");
	}
	if(end_stream_flag){
		printf("END_STREAM ");
	}
	printf("\n");
	printf("Stream identifier = %d\n", request_stream_identifier);
	
	printf("Lunghezza payload in byte: %d\n", rec->header.length);

	uint8_t* header_frame_payload = rec->payload;
	uint8_t pad_length = 0;
	uint8_t exclusive = 0;
	uint32_t stream_dependecy = 0;
	uint8_t weight = 0;
	if(padded_flag){
		pad_length = header_frame_payload[0];
		header_frame_payload ++;

		printf("pad_length = %d\n", pad_length);
	}
	if(priority_flag){
		exclusive = header_frame_payload[0] & 0x80; // primo bit
		stream_dependecy = header_frame_payload[0] & 0x7F << 24 | header_frame_payload[1] << 16 | header_frame_payload[2] << 8 | header_frame_payload[3];
		weight = header_frame_payload[4];
		header_frame_payload += 5;

		printf("exclusive = %s\n", exclusive?"TRUE":"FALSE");
		printf("stream_dependecy = %u\n", stream_dependecy);
		printf("weight = %d\n", weight);
	}

	uint64_t full_payload_length = rec->header.length - (padded_flag?(pad_length+1):0) - (priority_flag?5:0);

	uint8_t* full_payload = malloc(full_payload_length);
	memcpy(full_payload, header_frame_payload, full_payload_length);

	if(!end_headers_flag){
		struct logical_frame_wire_payload* continuation_frame;
		struct full_frame_list_node* cursor = frame_list;
		while(1){
			continuation_frame = NULL;
			cursor = cursor->next;
			if(cursor){
				continuation_frame = &(cursor->frame);
			}
			if(!continuation_frame){
				printf("ERRORE: non trovato continuation dopo header senza END_HEADERS");
				return;
			}
			if(continuation_frame->header.type != FRAME_TYPE_CONTINUATION){
				printf("ERRORE: ricevuto frame non CONTINUATION dopo HEADERS senza flag END_HEADERS");
				return;
			}
			if(continuation_frame->header.stream_identifier != rec->header.stream_identifier){
				printf("ERRORE: stream identifier continuation non corrisponde a quello di HEADERS");
				return;
			}

			printf("Letto frame CONTINUATION\n");
			// CONTINUATION non può avere padding quindi lo posso copiare direttamente tutto
			uint8_t* temp = malloc(full_payload_length + continuation_frame->header.length);
			memcpy(temp, full_payload, full_payload_length);
			memcpy(temp+full_payload_length, continuation_frame->payload, continuation_frame->header.length);
			free(full_payload);
			full_payload = temp;
			full_payload_length += continuation_frame->header.length;
			uint8_t do_break = continuation_frame->header.flags & FLAG_END_HEADERS;

			if(do_break){
				break;
			}
		}
	}
	// https://stackoverflow.com/a/3557272
	clock_t start = clock();
	struct header_list_node* first_header_node = header_list_from_field_block(full_payload, full_payload_length);
	clock_t end = clock();
	float seconds = (float)(end - start) / CLOCKS_PER_SEC;
	printf("Tempo di decodifica header field block: %fs\n", seconds);

	free(full_payload);

	struct header_list_node* node_cursor = first_header_node;
	printf("------- inizio stampa header ---------\n");
	while(node_cursor != NULL){
		if(node_cursor -> node_header != NULL){
			printf("NAME: |%s| VALUE: |%s|\n", node_cursor -> node_header -> nome, node_cursor -> node_header -> valore);
		}
		node_cursor = node_cursor -> next_node;
	}
	printf("------- fine stampa header ---------\n");

	send_response(request_stream_identifier, first_header_node);

	free_header_list(first_header_node);
}

void handle_continuation_frame(SSL* ssl, struct full_frame_list_node* frame_list){
	printf("ERRORE: frame continuation non previsto\n");
}
void handle_push_promise_frame(SSL* ssl, struct full_frame_list_node* frame_list){
	printf("ERRORE: frame push promise non previsto\n");
}
void handle_priority_frame(SSL* ssl, struct full_frame_list_node* frame_list){
	printf("Frame priority ignorato\n");
	return;
}
void handle_priority_update_frame(SSL* ssl, struct full_frame_list_node* frame_list){
	printf("Frame priority update ignorato\n");
	return;
}
void handle_data_frame(SSL* ssl, struct full_frame_list_node* frame_list){
	// Non ho bisogno di nessun entity body delle richieste per gestirle
	printf("Frame data ignorato\n");
	return;
}
void handle_rst_stream_frame(SSL* ssl, struct full_frame_list_node* frame_list, uint32_t** const rst_list_ptr){
	const struct logical_frame_wire_payload* rec = &(frame_list->frame);
	if(rec->header.length != 4){
		printf("ERRORE: length RST_STREAM != 4\n");
		return;
	}
	if(rec->header.stream_identifier == 0){
		printf("ERRORE: RST_STREAM stream id == 0\n");
		return;
	}
	uint32_t error_code = (rec->payload[0]<<24) | (rec->payload[1]<<16) | (rec->payload[2]<<8) | (rec->payload[3]);
	printf("Error code: %d (%s)\n", error_code, error_description_from_code(error_code));
	*rst_list_ptr = add_id_to_list(rec->header.stream_identifier, *rst_list_ptr);
	return;
}
void handle_window_update_frame(SSL* ssl, struct full_frame_list_node* frame_list, int32_t* const current_connection_window_size_ptr){
	const struct logical_frame_wire_payload* rec = &(frame_list->frame);
	if(rec->header.length != 4){
		printf("ERRORE: length WINDOW_UPDATE != 4\n");
		return;
	}
	if(rec->header.stream_identifier != 0){
		printf("Ignoro WINDOW_UPDATE con stream_identifier != 0\n");
		return;
	}
	uint32_t amount = (rec->payload[0]&0x7F)<<24 | rec->payload[1]<<16 | rec->payload[2]<<8 | rec->payload[3];
	*current_connection_window_size_ptr += amount;
	return;
}

char send_server_settings(SSL* ssl){
	/*
	Queste sono gli unici setting che trasmetto come server. Sono il più permissivi possibile
	per permettere al client di fare sostanzialmente quello che vuole

	SETTINGS_HEADER_TABLE_SIZE (0x01): settato per chiarezza a 4,096 che è il default

	SETTINGS_ENABLE_PUSH (0x02) settato per chiarezza a 0 (il server non mette mai 1)

	SETTINGS_MAX_CONCURRENT_STREAMS (0x03) unset: tengo il valore iniziale illimitato

	SETTINGS_INITIAL_WINDOW_SIZE (0x04) settato al massimo possibile (2^31-1)

	SETTINGS_MAX_FRAME_SIZE (0x05) settato al massimo possibile (2^24-1 , 3 byte a 1)

	SETTINGS_MAX_HEADER_LIST_SIZE (0x06) unset: tengo il valore iniziale illimitato 
	
	SETTINGS_NO_RFC7540_PRIORITIES (0x09) settato a 1
	*/
	struct logical_frame_header h;
	struct wire_frame_header w;
	struct logical_setting header_table_size, enable_push, initial_window_size, max_frame_size, rfc7540_priority;
	struct wire_setting w_s;
	int i, t;
	char* ptr;

	h.length = 5 * sizeof(struct wire_setting);
	h.type = FRAME_TYPE_SETTINGS;
	h.flags = 0;
	h.stream_identifier = 0;

	logical_to_wire_frame_header(&h, &w);

	header_table_size.id = SETTINGS_HEADER_TABLE_SIZE;
	header_table_size.value = INITIAL_SERVER_HEADER_TABLE_SIZE;

	enable_push.id = SETTINGS_ENABLE_PUSH;
	enable_push.value = 0;

	initial_window_size.id = SETTINGS_INITIAL_WINDOW_SIZE;
	initial_window_size.value = 0x7FFFFFFF;


	/* 
		Non scendere sotto a 0x4000 (16384) che è il valore di default.
		Un'impostazione con un valore inferiore viene considerata protocol error.
	*/
	max_frame_size.id = SETTINGS_MAX_FRAME_SIZE;
	max_frame_size.value = 0xFFFFFF;
	//max_frame_size.value = 0x4000;

	rfc7540_priority.id = SETTINGS_NO_RFC7540_PRIORITIES;
	rfc7540_priority.value = 1;

	



	// invio header
	ptr = (char*) &w;
	t = 0;
	while(t<sizeof(struct wire_frame_header)){
		i = SSL_write(ssl, ptr+t, sizeof(struct wire_frame_header)-t);
		if(i<=0){
			return RET_FALSE;
		}
		t+=i;
	}

	// invio singoli setting
	logical_to_wire_setting(&header_table_size, &w_s);
	ptr = (char*) &w_s;
	t = 0;
	while(t<sizeof(struct wire_setting)){
		i = SSL_write(ssl, ptr+t, sizeof(struct wire_setting)-t);
		if(i<=0){
			return RET_FALSE;
		}
		t+=i;
	}
	logical_to_wire_setting(&enable_push, &w_s);
	ptr = (char*) &w_s;
	t = 0;
	while(t<sizeof(struct wire_setting)){
		i = SSL_write(ssl, ptr+t, sizeof(struct wire_setting)-t);
		if(i<=0){
			return RET_FALSE;
		}
		t+=i;
	}
	logical_to_wire_setting(&initial_window_size, &w_s);
	ptr = (char*) &w_s;
	t = 0;
	while(t<sizeof(struct wire_setting)){
		i = SSL_write(ssl, ptr+t, sizeof(struct wire_setting)-t);
		if(i<=0){
			return RET_FALSE;
		}
		t+=i;
	}
	logical_to_wire_setting(&max_frame_size, &w_s);
	ptr = (char*) &w_s;
	t = 0;
	while(t<sizeof(struct wire_setting)){
		i = SSL_write(ssl, ptr+t, sizeof(struct wire_setting)-t);
		if(i<=0){
			return RET_FALSE;
		}
		t+=i;
	}
	logical_to_wire_setting(&rfc7540_priority, &w_s);
	ptr = (char*) &w_s;
	t = 0;
	while(t<sizeof(struct wire_setting)){
		i = SSL_write(ssl, ptr+t, sizeof(struct wire_setting)-t);
		if(i<=0){
			return RET_FALSE;
		}
		t+=i;
	}

	printf("Frame SETTINGS server inviato\n");
	return RET_TRUE;
}

// Ritorna 1 se è tutto OK, 0 se ci sono stati problemi
char read_connection_preface(SSL* ssl){
	char preface_str[CONNECTION_PREFACE_BUFFER_SIZE];
	int i = 0, t;
	while(i<CONNECTION_PREFACE_BUFFER_SIZE-1){
		t = SSL_read(ssl, preface_str+i, (CONNECTION_PREFACE_BUFFER_SIZE-1)-i);
		if(t<=0){
			return RET_FALSE;
		}
		i+=t;
	}
	preface_str[i]=0;
	return strcmp(preface_str, EXPECTED_CONNECTION_PREFACE) ? RET_FALSE : RET_TRUE;
}
void h_2_connection(SSL* ssl){
	char ok;
	struct full_frame_list_node *frame_list_head, *cursor, *prev;
	int child_pid;

	uint8_t* read_byte_buffer = malloc(MIN_H2_READ_BYTE_BUFFER_CAPACITY);
	int read_byte_buffer_size = 0;
	int read_byte_buffer_capacity = MIN_H2_READ_BYTE_BUFFER_CAPACITY;
	uint8_t read_result;
	int t;
	struct pollfd poll_arr[5];
	char found_frame_prev_iteration;


	/* Variabili send_manager */
	int command_socket, urgent_socket, headers_socket, data_socket;
	char *command_socket_path, *urgent_socket_path, *headers_socket_path, *data_socket_path;
	uint32_t* rst_list;
	uint32_t* opened_list;
	int32_t current_initial_window_size;
	int32_t current_connection_window_size; // byte che posso inviare con payload frame DATA in tutta la connessione
	uint32_t last_obtained_stream_id = 0;
	struct sockaddr_un server_addr;
	int64_t length, inizio_corrente, write_result;
	uint8_t* ptr;




	connection_socket_identifier = getpid();
	printf("CONNESSIONE HTTP/2\n");
	ok = read_connection_preface(ssl);
	if(!ok){
		printf("Errore read_connection_preface\n");
		return;
	}
	printf("Lettura connection preface ok\n");
	ok = send_server_settings(ssl);
	if(!ok){
		printf("Errore send_server_settings\n");
		return;
	}

	t = fcntl(SSL_get_fd(ssl), F_GETFL, NULL); 
	if(t==-1){
		perror("Errore fcntl F_GETFL");
		return;
	}
	t = fcntl(SSL_get_fd(ssl), F_SETFL, t | O_ASYNC | O_NONBLOCK);
	if(t == -1) { 
		perror("Errore fcntl F_SETFL");
		return;
	}


	/* Inizio setup send_manager */
	length = IPC_MSG_KERNEL_BUFFER_SIZE;

	command_socket = socket(AF_UNIX, SOCK_DGRAM, 0);
	if(command_socket == -1){
		perror("Errore creazione command_socket");
		return;
	}
	t = setsockopt(command_socket, SOL_SOCKET, SO_RCVBUF, &length, sizeof(length));
	if(t<0){
		perror("Errore setsockopt command_socket");
		return;
	}
	server_addr.sun_family = AF_UNIX;
	asprintf(&command_socket_path, COMMAND_SOCKET_PATH_TEMPLATE, connection_socket_identifier);
	strcpy(server_addr.sun_path, command_socket_path);
	t = sizeof(server_addr);
	unlink(server_addr.sun_path);
	t = bind(command_socket,(struct sockaddr*)&server_addr, t);
	if(t==-1){
		perror("Errore bind command_socket");
		return;
	}

	urgent_socket = socket(AF_UNIX, SOCK_DGRAM, 0);
	if(urgent_socket == -1){
		perror("Errore creazione urgent_socket");
		return;
	}
	t = setsockopt(urgent_socket, SOL_SOCKET, SO_RCVBUF, &length, sizeof(length));
	if(t<0){
		perror("Errore setsockopt urgent_socket");
		return;
	}
	server_addr.sun_family = AF_UNIX;
	asprintf(&urgent_socket_path, URGENT_SOCKET_PATH_TEMPLATE, connection_socket_identifier);
	strcpy(server_addr.sun_path, urgent_socket_path);
	t = sizeof(server_addr);
	unlink(server_addr.sun_path);
	t = bind(urgent_socket,(struct sockaddr*)&server_addr, t);
	if(t==-1){
		perror("Errore bind urgent_socket");
		return;
	}

	headers_socket = socket(AF_UNIX, SOCK_DGRAM, 0);
	if(headers_socket == -1){
		perror("Errore creazione headers_socket");
		return;
	}
	t = setsockopt(headers_socket, SOL_SOCKET, SO_RCVBUF, &length, sizeof(length));
	if(t<0){
		perror("Errore setsockopt headers_socket");
		return;
	}
	server_addr.sun_family = AF_UNIX;
	asprintf(&headers_socket_path, HEADERS_SOCKET_PATH_TEMPLATE, connection_socket_identifier);
	strcpy(server_addr.sun_path, headers_socket_path);
	t = sizeof(server_addr);
	unlink(server_addr.sun_path);
	t = bind(headers_socket,(struct sockaddr*)&server_addr, t);
	if(t==-1){
		perror("Errore bind headers_socket");
		return;
	}
	
	data_socket = socket(AF_UNIX, SOCK_DGRAM, 0);
	if(data_socket == -1){
		perror("Errore creazione data_socket");
		return;
	}
	t = setsockopt(data_socket, SOL_SOCKET, SO_RCVBUF, &length, sizeof(length));
	if(t<0){
		perror("Errore setsockopt data_socket");
		return;
	}
	server_addr.sun_family = AF_UNIX;
	asprintf(&data_socket_path, DATA_SOCKET_PATH_TEMPLATE, connection_socket_identifier);
	strcpy(server_addr.sun_path, data_socket_path);
	t = sizeof(server_addr);
	unlink(server_addr.sun_path);
	t = bind(data_socket,(struct sockaddr*)&server_addr, t);
	if(t==-1){
		perror("Errore bind data_socket");
		return;
	}


	current_initial_window_size = DEFAULT_INITIAL_FLOW_CONTROL_WINDOW_SIZE;
	current_connection_window_size = DEFAULT_INITIAL_FLOW_CONTROL_WINDOW_SIZE;

	// Malloc messi alla fine così se fallisce qualcosa nell'apertura dei socket ipc non devo fare i free
	rst_list = malloc(sizeof(uint32_t));
	rst_list[0]=0;
	opened_list = malloc(sizeof(uint32_t));
	opened_list[0]=0;
	/* Fine setup send_manager */

	poll_arr[0].fd = SSL_get_fd(ssl);
	poll_arr[1].fd = command_socket;
	poll_arr[2].fd = urgent_socket;
	poll_arr[3].fd = headers_socket;
	poll_arr[4].fd = data_socket;
	for(t=0; t<5; t++){
		poll_arr[t].events = POLLIN;
	}
	found_frame_prev_iteration = 0;
	while(1){
		if(!found_frame_prev_iteration){
			poll(poll_arr, 5, -1);
		}

		/* Inizio lettura connessione */
		read_result = read_bytes_nonblocking(ssl, read_byte_buffer, read_byte_buffer_size, read_byte_buffer_capacity, &read_byte_buffer, &read_byte_buffer_size, &read_byte_buffer_capacity);
		if(read_result == READ_RESULT_ERROR){
			break;
		}
		found_frame_prev_iteration = 0;
		frame_list_head = extract_frames_from_buffer(read_byte_buffer, read_byte_buffer_size, read_byte_buffer_capacity, &read_byte_buffer, &read_byte_buffer_size, &read_byte_buffer_capacity);


		if(frame_list_head){
			found_frame_prev_iteration = 1;
			printf("Ricevuta lista di frame:\n");
			cursor = frame_list_head;
			while(cursor){
				printf("type=%u flags=%u length=%u stream_identifier=%d\n", cursor->frame.header.type, cursor->frame.header.flags, cursor->frame.header.length, cursor->frame.header.stream_identifier);
				cursor = cursor->next;
			}
			switch(frame_list_head->frame.header.type){
				case FRAME_TYPE_SETTINGS:
					printf("Frame SETTINGS\n");
					handle_settings_frame(ssl, frame_list_head, &current_initial_window_size, &current_connection_window_size);
					break;
				case FRAME_TYPE_HEADERS:
					printf("Frame HEADERS\n");
					handle_headers_frame(ssl, frame_list_head);
					break;
				case FRAME_TYPE_CONTINUATION:
					printf("Frame CONTINUATION\n");
					handle_continuation_frame(ssl, frame_list_head);
					break;
				case FRAME_TYPE_PUSH_PROMISE:
					printf("Frame PUSH_PROMISE\n");
					handle_push_promise_frame(ssl, frame_list_head);
					break;
				case FRAME_TYPE_PRIORITY:
					printf("Frame PRIORITY\n");
					handle_priority_frame(ssl, frame_list_head);
					break;
				case FRAME_TYPE_PRIORITY_UPDATE:
					printf("Frame PRIORITY_UPDATE\n");
					handle_priority_update_frame(ssl, frame_list_head);
					break;
				case FRAME_TYPE_DATA:
					printf("Frame DATA\n");
					handle_data_frame(ssl, frame_list_head);
					break;
				case FRAME_TYPE_PING:
					printf("Frame PING\n");
					handle_ping_frame(ssl, frame_list_head);
					break;
				case FRAME_TYPE_RST_STREAM:
					printf("Frame RST_STREAM\n");
					handle_rst_stream_frame(ssl, frame_list_head, &rst_list);
					break;
				case FRAME_TYPE_WINDOW_UPDATE:
					printf("Frame WINDOW_UPDATE\n");
					handle_window_update_frame(ssl, frame_list_head, &current_connection_window_size);
					break;
				case FRAME_TYPE_GOAWAY:
					printf("Frame GOAWAY\n");
					handle_goaway_frame(ssl, frame_list_head);
					
					close(command_socket);
					close(urgent_socket);
					close(headers_socket);
					close(data_socket);
					unlink(command_socket_path);
					unlink(urgent_socket_path);
					unlink(headers_socket_path);
					unlink(data_socket_path);
					free(command_socket_path);
					free(urgent_socket_path);
					free(headers_socket_path);
					free(data_socket_path);
					free(rst_list);
					free(opened_list);
					
					// Messi anche qui perchè non passo per la fine del ciclo
					cursor = frame_list_head;
					while(cursor){
						free(cursor->frame.payload);
						prev = cursor;
						cursor = cursor->next;
						free(prev);
					}
					trim_dynamic_table_for_capacity(0);
					return;
				default:
					printf("Tipo frame sconosciuto\n");
			}
			
			cursor = frame_list_head;
			while(cursor){
				free(cursor->frame.payload);
				prev = cursor;
				cursor = cursor->next;
				free(prev);
			}
		}
		/* Fine lettura connessione */

		/* Inizio lettura IPC */
		ptr = read_ipc_msg_nonblocking(command_socket, &length, 0);
		if(ptr != NULL){
			printf("Ricevuto command: %s\n", ptr);
			if(!strncmp(ptr, NEW_STREAM_ID_CMD_PREFIX, strlen(NEW_STREAM_ID_CMD_PREFIX))){
				uint32_t new_stream_id = last_obtained_stream_id +2;
				char* msg;
				asprintf(&msg, "%d", new_stream_id);
				send_ipc_msg(ptr+strlen(NEW_STREAM_ID_CMD_PREFIX), msg, strlen(msg));
				last_obtained_stream_id = new_stream_id;
				free(msg);
				free(ptr);
				continue;
			}
			printf("Comando non riconosciuto\n");
			free(ptr);
			continue;
		}
		ptr = read_ipc_msg_nonblocking(urgent_socket, &length, 0);
		if(ptr != NULL){
			printf("Ricevuto frame urgent\n");
			// Alcuni frame urgenti (come RST_STREAM) possono essere inviati anche se ho ricevuto RST_STREAM
			inizio_corrente = 0;
			while(inizio_corrente<length){
				write_result = SSL_write(ssl, ptr+inizio_corrente, length-inizio_corrente);
				if(write_result > 0){
					inizio_corrente+=write_result;
				}else{
					int error_code = SSL_get_error(ssl, write_result);
					if( error_code != SSL_ERROR_WANT_READ && error_code != SSL_ERROR_WANT_WRITE ){
						printf("ERRORE SSL_write send_manager urgent non previsto: error code = %d\n", error_code);
						ERR_print_errors_fp(stdout);
						break;
					}
				}
			}
			free(ptr);
			continue;
		}
		ptr = read_ipc_msg_nonblocking(headers_socket, &length, 0);
		if(ptr != NULL){
			printf("Ricevuto frame headers\n");
			if(!is_frame_stream_rst(ptr, rst_list)){
				// Devo controllare che sia un frame headers perchè questo socket ipc viene usato anche per inviare frame PUSH_PROMISE che non aprono gli stream (vengono inviati su stream già aperti, dopo HEADERS)
				if(frame_type_from_frame_bytes(ptr) == FRAME_TYPE_HEADERS && !(flags_from_frame_bytes(ptr) & FLAG_END_STREAM)){
					opened_list = add_id_to_list(stream_id_from_frame_bytes(ptr), opened_list);
				}
				inizio_corrente = 0;
				while(inizio_corrente<length){
					write_result = SSL_write(ssl, ptr+inizio_corrente, length-inizio_corrente);
					if(write_result > 0){
						inizio_corrente+=write_result;
					}else{
						int error_code = SSL_get_error(ssl, write_result);
						if( error_code != SSL_ERROR_WANT_READ && error_code != SSL_ERROR_WANT_WRITE ){
							printf("ERRORE SSL_write send_manager headers non previsto: error code = %d\n", error_code);
							ERR_print_errors_fp(stdout);
							break;
						}
					}
				}
				if(flags_from_frame_bytes(ptr) & FLAG_END_STREAM){
					opened_list = remove_id_from_list(stream_id_from_frame_bytes(ptr), opened_list);
				}
			}else{
				printf("Frame coda headers scartato da send_manager (RST_STREAM)\n");
			}
			free(ptr);
			continue;
		}
		ptr = read_ipc_msg_nonblocking(data_socket, &length, MSG_PEEK);
		if(ptr != NULL){
			printf("Ricevuto frame data\n");
			if(is_frame_stream_rst(ptr, rst_list)){
				free(ptr);
				ptr = read_ipc_msg_nonblocking(data_socket, &length, 0);
				free(ptr);
				printf("Frame coda data scartato da send_manager (RST_STREAM)\n");
				continue;
			}

			// Il costo per il flow control di un singolo frame DATA è la sua lunghezza in byte - 9 (lunghezza del suo frame header)
			if((length - 9) <= current_connection_window_size && is_frame_stream_opened(ptr, opened_list)){
				free(ptr);
				ptr = read_ipc_msg_nonblocking(data_socket, &length, 0);
				inizio_corrente = 0;
				while(inizio_corrente<length){
					write_result = SSL_write(ssl, ptr+inizio_corrente, length-inizio_corrente);
					if(write_result > 0){
						inizio_corrente+=write_result;
					}else{
						int error_code = SSL_get_error(ssl, write_result);
						if( error_code != SSL_ERROR_WANT_READ && error_code != SSL_ERROR_WANT_WRITE ){
							printf("ERRORE SSL_write send_manager data non previsto: error code = %d\n", error_code);
							ERR_print_errors_fp(stdout);
							break;
						}
					}
				}
				current_connection_window_size -= (length - 9);
				if(flags_from_frame_bytes(ptr) & FLAG_END_STREAM){
					opened_list = remove_id_from_list(stream_id_from_frame_bytes(ptr), opened_list);
				}
			}
			free(ptr);
			continue;
		}
		/* Fine lettura IPC */
	}

	close(command_socket);
	close(urgent_socket);
	close(headers_socket);
	close(data_socket);
	unlink(command_socket_path);
	unlink(urgent_socket_path);
	unlink(headers_socket_path);
	unlink(data_socket_path);
	free(command_socket_path);
	free(urgent_socket_path);
	free(headers_socket_path);
	free(data_socket_path);
	free(rst_list);
	free(opened_list);

	// free della dynamic table
	trim_dynamic_table_for_capacity(0);
}

void h_1_1_connection(SSL* ssl){
	int content_length, num_header, i, j, t, resource_fd;
	char request_line_buffer[REQUEST_LINE_BUFFER_SIZE+1];
	char request_header_buffer[REQUEST_HEADER_BUFFER_SIZE];
	uint8_t response_file_chunk_buffer[CHUNK_MAX_LENGTH];
	struct http_header request_header_list[HEADER_LIST_SIZE];
	char* file_path_from_root;
	char* full_file_path;
	char* method;

	char free_full_response;
	char chunked_request;
	char keep_alive_ok;
	char has_body;
	char* full_response;
	char* str_ptr;
	uint64_t full_response_length;
	uint64_t file_content_length;

	printf("Client HTTP/1.1 connesso\n");
	while(1){
		content_length = 0;
		num_header = 0;
		file_path_from_root = NULL;
		full_file_path = NULL;
		free_full_response = 0;
		chunked_request = 0;
		keep_alive_ok = 0;
		t = 0;
		has_body = 0;
		while(t<REQUEST_LINE_BUFFER_SIZE && SSL_read(ssl, request_line_buffer+t, 1)){
			if(t>=1 && request_line_buffer[t]=='\n' && request_line_buffer[t-1] == '\r'){
				break;
			}
			t++;
		}
		request_line_buffer[t] = 0;
		printf("Request line: %s\n", request_line_buffer);
		

		method = request_line_buffer;
		for(i = 0; i<t; i++){
			if(request_line_buffer[i]==' '){
				request_line_buffer[i] = 0;
				if(file_path_from_root==NULL){
					file_path_from_root = request_line_buffer+i+1;
				}else{
					break;
				}
			}
		}
		
		request_header_list[0].nome = request_header_buffer;
		request_header_list[0].valore = NULL;
		t=0;
		while(t<REQUEST_HEADER_BUFFER_SIZE && SSL_read(ssl, request_header_buffer+t, 1)){
			if(request_header_list[num_header].valore == NULL && request_header_buffer[t]==':'){
				request_header_buffer[t] = 0;
				request_header_list[num_header].valore = request_header_buffer + t + 1;
			}else if(t>=1 && request_header_buffer[t] == '\n' && request_header_buffer[t-1] == '\r'){
				// fine riga singolo header
				if(request_header_buffer + t - request_header_list[num_header].nome == 1){
					// header finiti
					keep_alive_ok = 1;
					break;
				}
				request_header_buffer[t-1] = 0; // fine stringa header precedente
				
				if(!strcmp(request_header_list[num_header].nome, "Content-Length")){
					content_length = atol(request_header_list[num_header].valore);
				}else if(!strcmp(request_header_list[num_header].nome, "Transfer-Encoding") && !strcmp(request_header_list[num_header].nome, " chunked")){
					chunked_request = 1;
				}
				num_header++;
				request_header_list[num_header].nome = request_header_buffer + t + 1;  
				request_header_list[num_header].valore = NULL;
			}
			t++;
		}
		if(!keep_alive_ok){
			break;
		}

		// Scarto l'eventuale entity body
		for(i=0; i<content_length; i++){
			SSL_read(ssl, &t, 1);
		}
		if(chunked_request){
			while(1){
				char hex_str[100];
				i = 0;
				do{
					SSL_read(ssl, hex_str+i, 1);
					i++;
				}while(hex_str[(i-2)>=0?(i-2):0]!='\r'&&hex_str[(i-1)>=0?(i-1):0]!='\n');
				hex_str[i]=0;
				int chunk_length = strtol(hex_str, NULL, 16);
				for(i=0; i<chunk_length; i++){
					SSL_read(ssl, &t, 1);
				}
			}
		}

		if(file_path_from_root == NULL || file_path_from_root[0]!='/'){
			// Bad Request
			full_response = HTTP_1_1_400_RESPONSE;
			full_response_length = strlen(full_response);
			printf("Response 400\n");
			goto invio_response;
		}
		file_path_from_root++; // "/..." -> "..."

		if(!strlen(file_path_from_root)){
			file_path_from_root = HOMEPAGE_FILENAME;
		}
		full_file_path = malloc(strlen(file_path_from_root)+strlen(WEBSITE_ROOT_DIRECTORY)+1);
		sprintf(full_file_path, "%s%s", WEBSITE_ROOT_DIRECTORY, file_path_from_root);

		resource_fd = open(full_file_path, O_RDONLY);
		if(resource_fd==-1){
			full_response = HTTP_1_1_404_RESPONSE;
			full_response_length = strlen(full_response);
			printf("Response 404\n");
			goto invio_response;
		}
		
		full_response = strdup(HTTP_1_1_200_RESPONSE_HEADERS);
		full_response_length = strlen(full_response);
		has_body = 1;
		
		invio_response:
		t = 0;
		while(t<full_response_length){
			i = SSL_write(ssl, full_response+t, full_response_length-t);
			if(i<0){
				perror("Errore write response");
				break;
			}
			t += i;
		}
		if(has_body){
			while(1){
				t = read(resource_fd, response_file_chunk_buffer, CHUNK_MAX_LENGTH);
				if(t<=0){
					asprintf(&str_ptr, "0\r\n\r\n");
					t = 0;
					while(t<strlen(str_ptr)){
						i = SSL_write(ssl, str_ptr+t, strlen(str_ptr)-t);
						if(i<0){
							perror("Errore write chunk end");
							break;
						}
						t += i;
					}
					free(str_ptr);
					break;
				}
				j=t;
				asprintf(&str_ptr, "%x\r\n", t);
				for(i=0; i<strlen(str_ptr); i++){
					str_ptr[i] = toupper(str_ptr[i]);
				}
				t = 0;
				while(t<strlen(str_ptr)){
					i = SSL_write(ssl, str_ptr+t, strlen(str_ptr)-t);
					if(i<0){
						perror("Errore write chunk size");
						break;
					}
					t += i;
				}
				free(str_ptr);
				t = 0;
				while(t<j){
					i = SSL_write(ssl, response_file_chunk_buffer+t, j-t);
					if(i<0){
						perror("Errore write chunk payload");
						break;
					}
					t += i;
				}
				asprintf(&str_ptr, "\r\n");
				t = 0;
				while(t<strlen(str_ptr)){
					i = SSL_write(ssl, str_ptr+t, strlen(str_ptr)-t);
					if(i<0){
						perror("Errore write chunk end");
						break;
					}
					t += i;
				}
				free(str_ptr);
			}
			close(resource_fd);
		}
		printf("Response inviata\n");

		if(full_file_path!=NULL){
			free(full_file_path);
		}
		if(free_full_response){
			free(full_response);
		}
	}
	printf("Client HTTP/1.1 disconnesso\n");
}

void handle_connection(int socket_fd, SSL_CTX* ssl_ctx){
	int t;
	unsigned char* alpn_data_ptr = NULL;
	SSL* ssl = SSL_new(ssl_ctx);

	if(ssl==NULL){
		perror("Errore ssl null");
		ERR_print_errors_fp(stdout);
		goto close_connection;
	}
	t = SSL_set_fd(ssl, socket_fd);
	if(!t){
		perror("Errore ssl set fd");
		ERR_print_errors_fp(stdout);
		goto close_connection;
	}
	t = SSL_accept(ssl);
	if(t!=1){
		perror("Errore ssl accept");
		ERR_print_errors_fp(stdout);
		goto close_connection;
	}

	// Controllo protocollo selezionato ALPN
	SSL_get0_alpn_selected(ssl, (const unsigned char **) &alpn_data_ptr, &t);
	if(t == 2 && alpn_data_ptr[0] == 'h' && alpn_data_ptr[1] == '2'){
		h_2_connection(ssl);
	}else{
		// Se non è h2 la connessione viene trattata come HTTP/1.1
		h_1_1_connection(ssl);
	}

	close_connection:
	if(ssl){
		SSL_shutdown(ssl);
		SSL_free(ssl);
	}
	close(socket_fd);
	return;
}

int select_alpn_callback(SSL *ssl, const unsigned char **out, unsigned char *outlen, const unsigned char *in, unsigned int inlen, void *arg){
	int i, j, n_caratteri, n_protocolli;
	if(inlen <= 0){
		// There was no overlap between the client's supplied list and the server configuration
		return SSL_TLSEXT_ERR_ALERT_FATAL;
	}
	// calcolo numero protocolli
	n_protocolli = 0;
	i = 0;
	while(i<inlen){
		n_caratteri = in[i];
		i++;
		for(j=0; j<n_caratteri; j++){
			i++;
		}
		n_protocolli++;
	}

	if(H2_ENABLED){
		// Controllo h2
		j=0;
		for(i=0; i<n_protocolli; i++){
			n_caratteri = in[j];
			if(n_caratteri == 2 && in[j+1] == 'h' && in[j+2] == '2'){
				*outlen = 2;
				*out = in + j + 1;
				return SSL_TLSEXT_ERR_OK;
			}
			j+= (n_caratteri + 1);
		}
	}

	// Controllo http/1.1
	j=0;
	for(i=0; i<n_protocolli; i++){
		n_caratteri = in[j];
		if(n_caratteri == 8 && in[j+1] == 'h' && in[j+2] == 't'&& in[j+3] == 't'&& in[j+4] == 'p'&& in[j+5] == '/' && in[j+6] == '1'&& in[j+7] == '.'&& in[j+8] == '1'){
			*outlen = 8;
			*out = in + j + 1;
			return SSL_TLSEXT_ERR_OK;
		}
		j+= (n_caratteri + 1);
	}
	
	printf("Errore ALPN: nessun protocollo trovato\n");
	return SSL_TLSEXT_ERR_ALERT_FATAL;
}

int main(){
	SSL_CTX* ssl_ctx;
	const SSL_METHOD* method;
	
	int listen_socket, client_socket, t;
	

	//INIZIO COSTRUZIONE SSL CTX

	method = TLS_server_method();
	ssl_ctx = SSL_CTX_new(method);
	if(ssl_ctx==NULL){
		perror("Errore SSL context null");
		ERR_print_errors_fp(stdout);
		return -1;
	}

	SSL_CTX_set_min_proto_version(ssl_ctx, TLS1_VERSION);
	
	if(SSL_CTX_use_certificate_file(ssl_ctx, HTTPS_CERTIFICATE_PATH, SSL_FILETYPE_PEM)!=1){
		perror("Errore use certificate");
		ERR_print_errors_fp(stdout);
		return -1;
	}
	if(SSL_CTX_use_PrivateKey_file(ssl_ctx, HTTPS_PRIVATE_KEY_PATH, SSL_FILETYPE_PEM)!=1){
		perror("Errore use PrivateKey");
		ERR_print_errors_fp(stdout);
		return -1;
	}

	SSL_CTX_set_alpn_select_cb(ssl_ctx, &select_alpn_callback, NULL);

	SSL_CTX_set_mode(ssl_ctx, SSL_MODE_ENABLE_PARTIAL_WRITE);

	//FINE COSTRUZIONE SSL CTX

	listen_socket = socket(AF_INET, SOCK_STREAM, 0);
	if(listen_socket==-1){
		perror("Errore chiamata socket");
		return -1;
	}
	t = 1;
	t = setsockopt(listen_socket, SOL_SOCKET, SO_REUSEADDR,&t, sizeof(t));
	if(t<0){
		perror("Errore setsockopt addr");
		return -1;
	}
	t = 1;
	t = setsockopt(listen_socket, SOL_SOCKET, SO_REUSEPORT,&t, sizeof(t));
	if(t<0){
		perror("Errore setsockopt port");
		return -1;
	}
	local_addr.sin_family = AF_INET;
	local_addr.sin_port = htons(SERVER_PORT);
	t = bind(listen_socket, (struct sockaddr *) &local_addr, sizeof(struct sockaddr_in));
	if(t==-1){
		perror("Errore bind");
		return -1;
	}
	t = listen(listen_socket, QUEUE_LENGTH);
	if(t==-1){
		perror("Errore listen");
		return -1;
	}
	printf("Server running @ port %d\n", SERVER_PORT);
	while(1){
		t = sizeof(struct sockaddr_in);
		client_socket = accept(listen_socket, (struct sockaddr *)&remote_addr, &t);
		if(client_socket==-1){
			perror("Errore accept");
			continue;
		}
		t = fork();
		if(t==0){
			handle_connection(client_socket, ssl_ctx);
			printf("Disconnessione client\n");
			// Uccido tutti i processi discendenti
			kill(-1*getpid(), SIGKILL);
			exit(0);
		}
		close(client_socket);
	}

	//SSL_CTX_free(ssl_ctx);
}
