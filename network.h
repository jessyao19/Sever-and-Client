#ifndef NETWORK_H
#define NETWORK_H

#define DICT_TOTAL_BYTES 986 //have calculated using ftell()
#define SEGMENTS 256 //no. of segments in the dictionary file
#define MAX_BITS 256 //maximum no. of bits in bitcode 
#define COMPRESSION_DICT "compression.dict"
#define MSG_HDR_PL 9 //the no. of bytes of msg header & payload length fields
#define SESSION_BYTES 4 //the no. of bytes of the session ID 
#define NO_BITS 8 //the no. of bits in 1 byte
#define CONFIG_IP_PORT 6 //no. of bytes for IP addr. & port in config. file
#define EMPTY_DIR_BYTES 10 //no. of bytes in msg to send back to client 
#define FILE_SIZE_BYTES 17 //no. of bytes in msg to send back to client 
#define LISTEN_BACKLOG 128 //no. connections to queue up in system  


/** Stores the compression dictionary information */
struct bitcodes {
	uint8_t each_byte[DICT_TOTAL_BYTES]; //store each byte of the file 
	int code[SEGMENTS][MAX_BITS]; //each element will contain up to 28 bits
	//(0 or 1 as values) 
	int length_code[SEGMENTS]; //length of bitcode-used to read field 'code' 
};

/** Stores decompressed payload and the size of it */
struct decompressed_info {
	uint8_t* original_payload;
	int original_payload_size;
};

void send_error_msg(int clientsocket_fd);

void perform_shutdown(int clientsocket_fd, int serversocket_fd);

bool check_matching_bits(int i, int range, struct bitcodes bits_array, 
	int* bits_compressed, int start_idx_range);

struct decompressed_info* decompress(uint8_t* payload, int payload_length, 
	struct bitcodes bits_array);

int get_decimal(int temp_length_bits[NO_BITS]);

void puts_big_endian(uint64_t number, uint8_t* buffer);

void payload_len_endian(uint64_t number, uint8_t* send_to_client);

void compression_then_send(int task, uint8_t* payload_contents, int size, 
	struct bitcodes bits_array, int clientsocket_fd);

char* absolute_path(char* directory, char* fname);

void file_size_query(struct bitcodes bits_array, char* directory, 
	int clientsocket_fd, uint8_t requires_compress, uint8_t compression_bit, 
	uint8_t* payload, uint64_t payload_length);

void free_decompress_struct(struct decompressed_info* d1);

void dir_listing(struct bitcodes bits_array, char* directory, 
	int clientsocket_fd, uint8_t requires_compress);

void read_compressed_dictionary(struct bitcodes* bits_array);

bool check_shutdown(uint8_t type_digit, uint64_t payload_length);

void retrieve_id_occupied(int clientsocket_fd, char* target_fname, 
	char* full_file_path);

void retrieve_free_memory(uint8_t* send_back, uint8_t* payload, 
	char* target_fname, uint8_t* file_contents, char* full_file_path);

bool retrieve_detect_errors(bool target_found, bool invalid_file_range, DIR *d,
	int clientsocket_fd, char* target_fname, char* full_file_path, 
	uint8_t* payload);

uint32_t get_session_id(uint8_t session_ID[SESSION_BYTES]);

void retrieve_file(uint8_t* payload, uint64_t payload_length, 
	struct bitcodes bits_array, char* directory, int clientsocket_fd, 
	uint8_t compression_bit, uint8_t requires_compress, 
	uint32_t* child_session_id);

bool check_valid_type(uint8_t type_digit);

void setup_network(int serversocket_fd, in_addr_t ip_addr, 
	uint16_t port_number, struct sockaddr_in address);

void echo_task(uint8_t buffer[MSG_HDR_PL], struct bitcodes bits_array, 
	int clientsocket_fd, uint8_t* payload, uint64_t payload_length, 
	uint8_t compression_bit, uint8_t requires_compress);

#endif