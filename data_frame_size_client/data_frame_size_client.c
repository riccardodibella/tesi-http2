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
#include <stdint.h>

#define ROOT_CERT_PATH "root_ca_certs/firefox_cert_list_20230801.txt"

#define RET_OK 1
#define RET_ERROR 0

#define CONNECTION_PREFACE "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"

#define STATIC_HEADER_TABLE_SIZE 61

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

#define SETTINGS_HEADER_TABLE_SIZE 0x01
#define SETTINGS_ENABLE_PUSH 0x02
#define SETTINGS_MAX_CONCURRENT_STREAMS 0x03
#define SETTINGS_INITIAL_WINDOW_SIZE 0x04
#define SETTINGS_MAX_FRAME_SIZE 0x05
#define SETTINGS_MAX_HEADER_LIST_SIZE 0x06

#define FLAG_ACK 			0x01
#define FLAG_PRIORITY		0b00100000
#define FLAG_PADDED			0b00001000
#define FLAG_END_HEADERS	0b00000100
#define FLAG_END_STREAM		0b00000001


struct http_header{
	char* nome;
	char* valore;
};
struct header_list_node{
	struct http_header* node_header;
	struct header_list_node* next_node;
};

struct logical_frame_header{
	uint32_t length;
	uint8_t type;
	uint8_t flags;
	uint32_t stream_identifier;
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

// Variabili di stato HPACK
uint32_t current_dynamic_table_capacity = 4096; //4096 valore iniziale, viene aggiornato con i dynamic table size update
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
char read_logical_frame_header(SSL* ssl, struct logical_frame_header* destination){
	int t = 0, i;
	struct wire_frame_header temp;
	char* ptr = (char*) &temp;
	while(t<sizeof(struct wire_frame_header)){
		i = SSL_read(ssl, ptr+t, sizeof(struct wire_frame_header)-t);
		if(i<=0){
			return RET_ERROR;
		}
		t+=i;
	}
	wire_to_logical_frame_header(&temp, destination);
	return RET_OK;
}
uint8_t* read_wire_payload(SSL* ssl, uint32_t payload_length){
	int ok, start, i;
	uint8_t* to_return;

	// Potrebbe essere malloc(0)
	// "If size is 0, either a null pointer or a unique pointer that can be successfully passed to free() shall be returned"
	to_return = malloc(payload_length);

	// TODO TOGLIMI
	for(uint32_t j = 0; j<payload_length; j++){
		to_return[j]=0;
	}

	start = 0;
	while(start < payload_length){
		i = SSL_read(ssl, to_return + start, payload_length - start);
		if(i<=0){
			free(to_return);
			return NULL;
		}
		start += i;
	}
	return to_return;
}

struct logical_frame_wire_payload* read_full_frame(SSL* ssl){
	char ok;
	struct logical_frame_wire_payload* to_return = malloc(sizeof(struct logical_frame_wire_payload));
	ok = read_logical_frame_header(ssl, &(to_return->header));
	if(!ok){
		free(to_return);
		return NULL;
	}

	to_return->payload = read_wire_payload(ssl, to_return->header.length);

	return to_return;
}

char send_connection_preface(SSL* ssl){
	for(int i=0; i<strlen(CONNECTION_PREFACE); i++){
		int res = SSL_write(ssl, CONNECTION_PREFACE + i, 1);
		if(res<=0){
			return RET_ERROR;
		}
	}
	return RET_OK;
}
char send_client_settings(SSL* ssl){
	/*
	SETTINGS_HEADER_TABLE_SIZE (0x01): settato per chiarezza a 4,096 che è il default

	SETTINGS_ENABLE_PUSH (0x02): 0 non voglio push in questo client

	SETTINGS_MAX_CONCURRENT_STREAMS (0x03) unset: tengo il valore iniziale illimitato

	SETTINGS_INITIAL_WINDOW_SIZE (0x04) settato al massimo possibile (2^31-1)

	SETTINGS_MAX_FRAME_SIZE (0x05) settato al massimo possibile (2^24-1 , 3 byte a 1)

	SETTINGS_MAX_HEADER_LIST_SIZE (0x06) unset: tengo il valore iniziale illimitato 
	*/
	struct logical_frame_header logical_header;
	struct wire_frame_header wire_header;
	struct logical_setting logical_setting;
	struct wire_setting wire_setting;
	int res, t;
	uint8_t* ptr;

	// Frame header
	logical_header.length = 4 * sizeof(struct wire_setting);
	logical_header.type = FRAME_TYPE_SETTINGS;
	logical_header.flags = 0;
	logical_header.stream_identifier = 0;
	logical_to_wire_frame_header(&logical_header, &wire_header);
	ptr = (uint8_t*) &wire_header;
	t = 0;
	while(t<sizeof(struct wire_frame_header)){
		res = SSL_write(ssl, ptr+t, sizeof(struct wire_frame_header)-t);
		if(res<=0){
			return RET_ERROR;
		}
		t+=res;
	}

	// SETTINGS_HEADER_TABLE_SIZE
	logical_setting.id = SETTINGS_HEADER_TABLE_SIZE;
	logical_setting.value = 4096;
	logical_to_wire_setting(&logical_setting, &wire_setting);
	ptr = (uint8_t*) &wire_setting;
	t = 0;
	while(t<sizeof(struct wire_setting)){
		res = SSL_write(ssl, ptr+t, sizeof(struct wire_setting)-t);
		if(res<=0){
			return RET_ERROR;
		}
		t+=res;
	}
	// SETTINGS_ENABLE_PUSH
	logical_setting.id = SETTINGS_ENABLE_PUSH;
	logical_setting.value = 0;
	logical_to_wire_setting(&logical_setting, &wire_setting);
	ptr = (uint8_t*) &wire_setting;
	t = 0;
	while(t<sizeof(struct wire_setting)){
		res = SSL_write(ssl, ptr+t, sizeof(struct wire_setting)-t);
		if(res<=0){
			return RET_ERROR;
		}
		t+=res;
	}
	// SETTINGS_INITIAL_WINDOW_SIZE
	logical_setting.id = SETTINGS_INITIAL_WINDOW_SIZE;
	logical_setting.value = 0x7FFFFFFF;
	logical_to_wire_setting(&logical_setting, &wire_setting);
	ptr = (uint8_t*) &wire_setting;
	t = 0;
	while(t<sizeof(struct wire_setting)){
		res = SSL_write(ssl, ptr+t, sizeof(struct wire_setting)-t);
		if(res<=0){
			return RET_ERROR;
		}
		t+=res;
	}
	// SETTINGS_MAX_FRAME_SIZE
	logical_setting.id = SETTINGS_MAX_FRAME_SIZE;
	logical_setting.value = 0x00FFFFFF;
	logical_to_wire_setting(&logical_setting, &wire_setting);
	ptr = (uint8_t*) &wire_setting;
	t = 0;
	while(t<sizeof(struct wire_setting)){
		res = SSL_write(ssl, ptr+t, sizeof(struct wire_setting)-t);
		if(res<=0){
			return RET_ERROR;
		}
		t+=res;
	}

	return RET_OK;
}
char send_settings_ack(SSL* ssl){
	struct logical_frame_header logical_header;
	struct wire_frame_header wire_header;
	int res, t;
	uint8_t* ptr;

	logical_header.length = 0;
	logical_header.type = FRAME_TYPE_SETTINGS;
	logical_header.flags = FLAG_ACK;
	logical_header.stream_identifier = 0;
	logical_to_wire_frame_header(&logical_header, &wire_header);
	ptr = (char*) &wire_header;
	t = 0;
	while(t<sizeof(struct wire_frame_header)){
		res = SSL_write(ssl, ptr+t, sizeof(struct wire_frame_header)-t);
		if(res<=0){
			return RET_ERROR;
		}
		t+=res;
	}
	return RET_OK;
}
char send_window_update(SSL* ssl, uint32_t stream_id, uint32_t amount){
	struct logical_frame_header logical_header;
	struct wire_frame_header wire_header;
	int res, t;
	uint8_t* ptr;
	uint32_t data;
	if(amount==0){
		return RET_OK;
	}
	logical_header.length = 4;
	logical_header.type = FRAME_TYPE_WINDOW_UPDATE;
	logical_header.flags = 0;
	logical_header.stream_identifier = stream_id;
	logical_to_wire_frame_header(&logical_header, &wire_header);
	ptr = (char*) &wire_header;
	t = 0;
	while(t<sizeof(struct wire_frame_header)){
		res = SSL_write(ssl, ptr+t, sizeof(struct wire_frame_header)-t);
		if(res<=0){
			return RET_ERROR;
		}
		t+=res;
	}
	data = htonl(amount);
	t=0;
	while(t<sizeof(data)){
		res = SSL_write(ssl, (&data)+t, sizeof(data)-t);
		if(res<=0){
			return RET_ERROR;
		}
		t+=res;
	}

	return RET_OK;
}

uint32_t get_next_client_stream_identifier(){
	static int last_used_id = 0;
	if(last_used_id == 0){
		last_used_id = 1;
		return last_used_id;
	}
	last_used_id += 2;
	return last_used_id;
}
struct logical_frame_wire_payload* header_frame_from_header_list(struct http_header* list, int length){
	/* 
		Ho "sicuramente" header più corti di 16KB quindi non uso mai continuation.
		Per fare la cosa più semplice possibile codifico tutto come Literal Header Field without Indexing,
		sia nome che valore sono codificati come literal, non viene codificato niente con Huffman.
		Codifico solo stringhe più corte di 2^7-1 = 127 caratteri 127 non è accettabile perchè avere
		tutti 1 come numero vuole già dire "valore su più byte").

		Struttura del singolo wire header:
		1 byte 0x00 (Literal Header Field without Indexing -- New Name)
		1 byte lunghezza nome
		... byte nome
		1 byte lunghezza valore
		... byte valore
	*/

	int number_of_chars = 0;
	for(int i=0; i<length; i++){
		if(strlen(list[i].nome)>=127 || strlen(list[i].valore)>=127){
			printf("ERRORE: nome o valore header più lungo di 126 caratteri\n");
			return NULL;
		}
		number_of_chars += strlen(list[i].nome)+strlen(list[i].valore);
	}
	int total_frame_payload_length = 3*length + number_of_chars;

	struct logical_frame_wire_payload* to_return = malloc(sizeof(struct logical_frame_wire_payload));
	to_return->header.stream_identifier = get_next_client_stream_identifier();
	to_return->header.type = FRAME_TYPE_HEADERS;
	to_return->header.flags = FLAG_END_HEADERS | FLAG_END_STREAM;
	to_return->header.length = total_frame_payload_length;
	to_return->payload = malloc(total_frame_payload_length);
	int payload_cursor = 0;
	for(int i=0; i<length; i++){
		to_return->payload[payload_cursor++] = 0;
		to_return->payload[payload_cursor++] = strlen(list[i].nome);
		for(int j=0; j<strlen(list[i].nome); j++){
			to_return->payload[payload_cursor++] = list[i].nome[j];
		}
		to_return->payload[payload_cursor++] = strlen(list[i].valore);
		for(int j=0; j<strlen(list[i].valore); j++){
			to_return->payload[payload_cursor++] = list[i].valore[j];
		}
	}
	return to_return;
}

int main(){
	char* server_name;
	char* resource_rel_path = NULL;
	SSL* ssl = NULL;
	SSL_CTX* ssl_ctx = NULL;
	const SSL_METHOD* client_method;
	X509* peer_certificate;
	long ssl_verify_result;
	struct hostent* resolved_addr;
	struct sockaddr_in remote_addr;
	int s; // socket
	int i;
	int res;
	uint8_t alpn_protos_array[] = {
		2, 'h', '2',
		8, 'h', 't', 't', 'p', '/', '1', '.', '1'
	};
	int alpn_protos_array_length = sizeof(alpn_protos_array);
	int alpn_selected_length;
	char* alpn_selected_name;
	char ok;
	struct logical_frame_wire_payload* p;
	struct wire_frame_header w_h;
	struct http_header* request_header_list;
	int request_header_list_size;
	char* resource_arr[]={
		"github.com",
		"www.google.com",
		"www.wikipedia.org",
		"dotnet.microsoft.com/en-us/",
		"www.cloudflare.com",
		"www.keycdn.com",
		"blog.chromium.org",
		"www.ietf.org",
		"www.youtube.com",
		"www.android.com",
		"www.aruba.it/home.aspx",
		"chat.openai.com/auth/login",
		"www.nginx.com",
		"www.shopify.com",
		"www.rfc-editor.org/rfc/rfc9113",
		"stem.elearning.unipd.it",
		"www.duckdns.org/css/ducky-16.css",
	};
	client_method = TLS_client_method();
	ssl_ctx = SSL_CTX_new(client_method);
	if(ssl_ctx == NULL){
		perror("Errore ssl context NULL");
		ERR_print_errors_fp(stdout);
		return -1;
	}
	// In man ssl_ctx_new è scritto di fare così per evitare di usare le versioni tanto vecchie non sicure
	//SSL_CTX_set_min_proto_version(ssl_ctx, TLS1_VERSION);
	
	// Impostazioni verifica certificati
	// Se si trova un problema si interrompe immediatamente l'handshake
	//SSL_CTX_set_verify(ssl_ctx, SSL_VERIFY_PEER, NULL);
	
	// se si vuole finire comunque l'handshake e non chiudere la connessione anche in caso di problemi:
	SSL_CTX_set_verify(ssl_ctx, SSL_VERIFY_NONE, NULL);
	

	/*if(!SSL_CTX_load_verify_locations(ssl_ctx, ROOT_CERT_PATH, NULL)){
		printf("ATTENZIONE: nessun certificato radice caricato.\n");
	}else{
		printf("Certificati radice caricati correttamente.\n");
	}*/

	
	if(!SSL_CTX_set_alpn_protos(ssl_ctx, alpn_protos_array, alpn_protos_array_length)){
		printf("Protocolli ALPN impostati con successo\n");
	}else{
		printf("Errore impostazione protocolli ALPN\n");
		ERR_print_errors_fp(stdout);
		return -1;
	}
	printf("Fine creazione context openssl\n");
	printf("Numero di risorse da richiedere: %lu\n", sizeof(resource_arr)/sizeof(resource_arr[0]));
	for(int indice_server = 0; indice_server < sizeof(resource_arr)/sizeof(resource_arr[0]); indice_server++){
		server_name = strdup(resource_arr[indice_server]);
		resource_rel_path = NULL;
		for(i=0; i<strlen(server_name); i++){
			if(server_name[i]=='/'){
				resource_rel_path = strdup(server_name+i);
				server_name[i]=0;
				break;
			}
		}
		if(resource_rel_path==NULL){
			resource_rel_path = strdup("/");
		}
		printf("\n\nserver_name = %s resource_rel_path = %s\n", server_name, resource_rel_path);

		s=socket(AF_INET, SOCK_STREAM, 0);
		if (s==-1) {
			perror("Socket fallita");
			printf("%d\n",errno);
			goto close_connection;
		}
		remote_addr.sin_family = AF_INET;
		remote_addr.sin_port = htons(443);

		resolved_addr = gethostbyname(server_name);
		if(resolved_addr == NULL){
			printf("Gethostbyname fallita\n");
			goto close_connection;
		}
		remote_addr.sin_addr.s_addr = *(unsigned int*) resolved_addr->h_addr_list[0];

		if(connect(s,(struct sockaddr *) &remote_addr,sizeof(struct sockaddr_in)) ==-1) {
			perror("Connect Fallita\n");
			goto close_connection;
		}

		ssl = SSL_new(ssl_ctx);
		if(ssl==NULL){
			perror("Errore ssl SSL_new NULL");
			ERR_print_errors_fp(stdout);
			goto close_connection;
		}

		SSL_set_tlsext_host_name(ssl, server_name);
		if(!SSL_set_fd(ssl, s)){
			perror("Errore SSL set fd");
			ERR_print_errors_fp(stdout);
			goto close_connection;
		}
		if(SSL_connect(ssl)!=1){
			printf("SSL connect fallita\n");
			ERR_print_errors_fp(stdout);
			printf("ssl_get_verify_result: %ld\n", SSL_get_verify_result(ssl));
			goto close_connection;
		}
		peer_certificate = SSL_get_peer_certificate(ssl);
		if(peer_certificate == NULL){
			printf("peer certificate NULL");
		}else{		
			X509_free(peer_certificate);
		}

		SSL_get0_alpn_selected(ssl, (const unsigned char **) &alpn_selected_name, &alpn_selected_length);
		if(alpn_selected_length==2&&alpn_selected_name[0]=='h'&&alpn_selected_name[1]=='2'){
		}else{
			printf("HTTP/2 NON SUPPORTATO\n");
			goto close_connection;
		}

		ok = send_connection_preface(ssl);
		if(!ok){
			printf("Errore send_connection_preface\n");
			goto close_connection;
		}
		ok = send_client_settings(ssl);
		if(!ok){
			printf("Errore send_client_settings\n");
			goto close_connection;
		}
		
		p = read_full_frame(ssl);
		if(p==NULL){
			printf("Errore nella ricezione del frame\n");
			goto close_connection;
		}
		if(p->header.type != FRAME_TYPE_SETTINGS){
			printf("ERRORE: frame type != FRAME_TYPE_SETTINGS (%02x)\n", FRAME_TYPE_SETTINGS);
			goto close_connection;
		}
		free(p->payload);
		free(p);
		send_settings_ack(ssl);
		if(p==NULL){
			printf("Errore send_settings_ack\n");
			goto close_connection;
		}
		while(1){
			p = read_full_frame(ssl);
			if(p==NULL){
				printf("Errore nella ricezione del frame\n");
				goto close_connection;
			}
			if(p->header.type != FRAME_TYPE_SETTINGS){
				continue;
			}
			if(!(p->header.flags & FLAG_ACK)){
				continue;
			}
			if(p->header.length != 0){
				printf("ERRORE: ricevuto frame SETTINGS ACK con length != 0\n");
				goto close_connection;
			}
			free(p->payload);
			free(p);
			break;
		}

		request_header_list_size = 4;
		request_header_list = malloc(request_header_list_size * sizeof(struct http_header));
		request_header_list[0].nome = strdup(":method");
		request_header_list[0].valore = strdup("GET");

		request_header_list[1].nome = strdup(":path");
		request_header_list[1].valore = strdup(resource_rel_path);

		request_header_list[2].nome = strdup(":scheme");
		request_header_list[2].valore = strdup("https");

		request_header_list[3].nome = strdup(":authority");
		request_header_list[3].valore = strdup(server_name);

		p = header_frame_from_header_list(request_header_list, request_header_list_size);
		logical_to_wire_frame_header(&(p->header), &w_h);
		i = 0;
		while(i<sizeof(struct wire_frame_header)){
			res = SSL_write(ssl, ((uint8_t*)&w_h)+i, sizeof(struct wire_frame_header)-i);
			if(res<=0){
				printf("Errore invio HEADERS request (frame header)\n");
				goto close_connection;
			}
			i+=res;
		}
		i = 0;
		while(i<p->header.length){
			res = SSL_write(ssl, p->payload+i, p->header.length-i);
			if(res<=0){
				printf("Errore invio HEADERS request (frame payload)\n");
				goto close_connection;
			}
			i+=res;
		}
		free(p->payload);
		free(p);
		while(p=read_full_frame(ssl)){
			switch(p->header.type){
				case FRAME_TYPE_GOAWAY:
					printf("Ricevuto frame GOAWAY\n");
					uint32_t last_stream_id = p->payload[0]<<24|p->payload[1]<<16|p->payload[2]<<8|p->payload[3];
					printf("Last-Stream-ID: %u\n", last_stream_id);
					uint32_t error_code = p->payload[4]<<24|p->payload[5]<<16|p->payload[6]<<8|p->payload[7];
					printf("Error Code: %u\n", error_code);
					printf("Error description: %s\n", error_description_from_code(error_code));
					printf("Additional Debug Data: |");
					for(i=8; i<p->header.length; i++){
						printf("%c", p->payload[i]);
					}
					printf("|\n");
					free(p->payload);
					free(p);
					goto close_connection;
				
				case FRAME_TYPE_HEADERS:
					uint32_t request_stream_identifier = p->header.stream_identifier;

					uint8_t priority_flag = p->header.flags & FLAG_PRIORITY;
					uint8_t padded_flag = p->header.flags & FLAG_PADDED;
					uint8_t end_headers_flag = p->header.flags & FLAG_END_HEADERS;
					uint8_t end_stream_flag = p->header.flags & FLAG_END_STREAM;

					uint8_t* header_frame_payload = p->payload;
					uint8_t pad_length = 0;
					uint8_t exclusive = 0;
					uint32_t stream_dependecy = 0;
					uint8_t weight = 0;
					if(padded_flag){
						pad_length = header_frame_payload[0];
						header_frame_payload ++;
					}
					if(priority_flag){
						exclusive = header_frame_payload[0] & 0x80; // primo bit
						stream_dependecy = header_frame_payload[0] & 0x7F << 24 | header_frame_payload[1] << 16 | header_frame_payload[2] << 8 | header_frame_payload[3];
						weight = header_frame_payload[4];
						header_frame_payload += 5;
					}

					uint64_t full_payload_length = p->header.length - (padded_flag?(pad_length+1):0) - (priority_flag?5:0);

					uint8_t* full_payload = malloc(full_payload_length);
					memcpy(full_payload, header_frame_payload, full_payload_length);

					if(!end_headers_flag){
						struct logical_frame_wire_payload* continuation_frame = NULL;
						while(1){
							continuation_frame = read_full_frame(ssl);
							if(!continuation_frame){
								printf("ERRORE: non trovato continuation dopo header senza END_HEADERS");
								goto close_connection;
							}
							if(continuation_frame->header.type != FRAME_TYPE_CONTINUATION){
								printf("ERRORE: ricevuto frame non CONTINUATION dopo HEADERS senza flag END_HEADERS");
								goto close_connection;
							}
							if(continuation_frame->header.stream_identifier != p->header.stream_identifier){
								printf("ERRORE: stream identifier continuation non corrisponde a quello di HEADERS");
								goto close_connection;
							}
							// CONTINUATION non può avere padding quindi lo posso copiare direttamente tutto
							uint8_t* temp = malloc(full_payload_length + continuation_frame->header.length);
							memcpy(temp, full_payload, full_payload_length);
							memcpy(temp+full_payload_length, continuation_frame->payload, continuation_frame->header.length);
							free(full_payload);
							full_payload = temp;
							full_payload_length += continuation_frame->header.length;
							uint8_t do_break = continuation_frame->header.flags & FLAG_END_HEADERS;
							free(continuation_frame->payload);
							free(continuation_frame);

							if(do_break){
								break;
							}
						}
					}

					struct header_list_node* first_header_node = header_list_from_field_block(full_payload, full_payload_length);

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

					free_header_list(first_header_node);
					break;

				case FRAME_TYPE_DATA:
					printf("DATA: %d%s\n", p->header.length, (p->header.flags & FLAG_END_STREAM) ?" END_STREAM":"");
					/*
					printf("------ inizio stampa frame data ------\n");
					for(i=0; i<p->header.length; i++){
						printf("%c", p->payload[i]);
					}
					printf("\n------  fine stampa frame data  ------\n");
					*/
					ok = send_window_update(ssl, p->header.stream_identifier, p->header.length);
					if(!ok){
						printf("Errore send_window_update stream\n");
						free(p->payload);
						free(p);
						goto close_connection;
					}
					ok = send_window_update(ssl, 0, p->header.length);
					if(!ok){
						printf("Errore send_window_update connection\n");
						free(p->payload);
						free(p);
						goto close_connection;
					}
					break;
			}
			ok = 0;
			if((p->header.type == FRAME_TYPE_DATA || p->header.type == FRAME_TYPE_HEADERS) && (p->header.flags & FLAG_END_STREAM)){
				ok = 1;
			}
			free(p->payload);
			free(p);
			if(ok){
				break;
			}
		}
		close_connection:
		printf("Chiusura connessione\n");
		free(server_name);
		free(resource_rel_path);
		SSL_shutdown(ssl);
		close(s);
		SSL_free(ssl);
	}
	SSL_CTX_free(ssl_ctx);
	printf("Fine.\n");
}
