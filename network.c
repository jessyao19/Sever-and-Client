#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <pthread.h>
#include <assert.h>
#include <arpa/inet.h>
#include <stdbool.h>
#include <endian.h>
#include <dirent.h>
#include <sys/mman.h> 

#include "network.h"

/** 
Called if client request has invalid type field or other errors. 
Error msg has type digit 0xf and no payload. 
*/
void send_error_msg(int clientsocket_fd) {
	uint8_t error_buf[MSG_HDR_PL] = {0xf0, 0x00, 0x00, 0x00, 0x00, 0x00, 
		0x00, 0x00, 0x00};
	write(clientsocket_fd, error_buf, MSG_HDR_PL);
}

/**
A Shutdown command has been sent. 
Server and client connections must close. 
*/
void perform_shutdown(int clientsocket_fd, int serversocket_fd) {
	close(clientsocket_fd); //Close client/child fildes
	close(serversocket_fd);
	kill(getppid(), SIGUSR1); //close server/parent fildes
}

/** 
Check if the bits(in a certain range) in bits_compressed,
matches to the current bitcode(1st param.) being compared to in dictionary. 
Return true if same.
*/
bool check_matching_bits(int i, int range, struct bitcodes bits_array, 
	int* bits_compressed, int start_idx_range) {
	for(int x = 0; x < range; x++) { //compare if bitcodes match
		if(bits_array.code[i][x] != bits_compressed[start_idx_range + x]) {
			return false;
		}
	}
	return true;
}

/** 
Decompresses the payload received from client by reading 
from the compressed dictionary(3rd parameter). 
Passes in the compressed payload and its size to get the original payload. 
Returns the decompressed payload. 
*/
struct decompressed_info* decompress(uint8_t* payload, int payload_length, 
	struct bitcodes bits_array) {
	//Get total no. of bits in payload. 
	//Ignore the last byte in the payload(as it stores the padding length)
	//count no. of bits in 2nd last byte(because it is a part of the payload)
	int bits_padded = payload[payload_length - 1];
	int second_last_bits = 8 - bits_padded; 

	//stores the individual bits of the compressed msg(excluding padding bits)
	//Only 1's & 0's
	int* bits_compressed; 
	int bits_compressed_size = ((payload_length - 2) * NO_BITS) + 
		second_last_bits; 
	bits_compressed = malloc(bits_compressed_size * sizeof(int));
	
	//Extract bits(1's & 0's) from compressed payload bytes into the int* ptr
	int ctr = 0;
	for(int i = 0; i < payload_length - 2; i++) { 
		for(int j = 7; j>= 0; j--) {
			bits_compressed[ctr] = (int)((payload[i] >> j) & 1);
			ctr++;
		}
	}

	//Put the bits(not padding) from the 2nd last byte of payload 
	for(int i = 7; i >= bits_padded; i--) { 
		bits_compressed[ctr] = (int)((payload[payload_length - 2] >> i) & 1);
		ctr++;
	}

	//Find the corresponding bitcodes in the int*
	int start_idx_range = 0;
	int end_idx_range = 0; 
	//Store decompressed(original) payload bytes. realloc() later if needed
	uint8_t* decompressed_payload = malloc(1 * sizeof(uint8_t));
	int decompressed_payload_length = 0; //no. of original bytes found
	bool original_byte_found = false;
	bool bitcodes_match = true;
	int range = 0;

	//Search through compressed dict.(struct) to get 'original' byte
	//Outer while loop iterates until all bytes from decomp. payload found
	//Inner while() will run until one byte from original payload is found
	while(end_idx_range < bits_compressed_size) {
		original_byte_found = false; 
		while(!original_byte_found) { 
			range = end_idx_range - start_idx_range + 1; 
			for(int i = 0; i < SEGMENTS; i++) {
				bitcodes_match = true;
				if(bits_array.length_code[i] == range) { 
					//compare if bitcodes match
					bitcodes_match = check_matching_bits(i, range, bits_array,
						bits_compressed, start_idx_range);

					if(bitcodes_match) {
						original_byte_found = true;
						if(decompressed_payload_length == 0) { //Get idx/hex
							decompressed_payload[decompressed_payload_length]
								= (uint8_t)i;
						}else{ //expand the *array for next original byte 
							decompressed_payload = realloc(decompressed_payload,
								(decompressed_payload_length + 1) * 
								sizeof(uint8_t));
							decompressed_payload[decompressed_payload_length] =
								(uint8_t)i;
						}
						decompressed_payload_length++;
						break;
					}
				}
			}

			if(!original_byte_found) {
				end_idx_range++;
			}
		}
		end_idx_range++;
		start_idx_range = end_idx_range;
	}

	//Put decompressed payload into a struct ptr + decompressed payload_length
	struct decompressed_info* decompress1 = malloc(1 * 
		sizeof(struct decompressed_info));
	decompress1->original_payload = malloc(decompressed_payload_length* 
		sizeof(uint8_t));

	//Copy payload 
	memcpy(decompress1->original_payload, decompressed_payload, 
		decompressed_payload_length);
	decompress1->original_payload_size = decompressed_payload_length;

	free(decompressed_payload);
	free(bits_compressed);
	return decompress1;
}

/** 
Convert a uint8_t array(with 1's & 0's) into an integer 
*/
int get_decimal(int temp_length_bits[NO_BITS]) {
	int result = 0;
	int add = 128; //halve each iteration in for loop

	for(int i = 0; i < 8; i++) {
		if(temp_length_bits[i] == 1) {
			result = result + add;
		}
		add = add/2;
	}
	return result;
}

/**
Write uint64_t to buffer in big endian(network order).
Used for File size query & writing the file size into last 8
bytes of the msg sent back to client.
*/
void puts_big_endian(uint64_t number, uint8_t* buffer) {
	int shift = 56;
	for(int idx = MSG_HDR_PL; idx < 17; idx++) {
		buffer[idx] = (uint8_t) ((number >> shift) & 0xff);
		shift = shift- 8; //56,48,40,32,24,16,8,0
	}
}

/** 
Put payload length into the 2nd field of msg 
to be sent back to client-bytes [1,8] 
*/
void payload_len_endian(uint64_t number, uint8_t* send_to_client) {
	int shift = 56; 
	for(int idx = 1; idx < MSG_HDR_PL; idx++) {
		send_to_client[idx] = (uint8_t) ((number >> shift) & 0xff);
		shift = shift - 8; 
	}
}

/** 
Receives normal payload and the length of it(size).
Compression is applied, type digit is set accordingly depending on task.
Compression bit is set to 1 then  msg is sent to the client.
*/
void compression_then_send(int task, uint8_t* payload_contents, int size, 
	struct bitcodes bits_array, int clientsocket_fd) {

	//Use dictionary and figure out the length of payload 
	int sum_length = 0; 
	int lookup = 0; //lookup or 'key'
	for(int i = 0; i < size; i++) { 
		lookup = (int)payload_contents[i]; 
		sum_length = sum_length + bits_array.length_code[lookup]; 
	}

	//Figure out if padding required or not 
	bool padding_applied = false;
	int no_bits_pad = 0;
	if(sum_length % 8 != 0) {
		padding_applied = true;
		no_bits_pad = 8 - (sum_length % 8);
	}
	//Add the padding to original length
	int total_space = sum_length + no_bits_pad; 
	int* compressed_binary = malloc(total_space * sizeof(int));  

	int x = 0;
	for(int i = 0; i < size; i++) { 
		lookup = payload_contents[i]; 
		for(int j = 0; j < bits_array.length_code[lookup]; j++) { 
			compressed_binary[x] = bits_array.code[lookup][j];
			x++;
		}
	}

	if(padding_applied) { //need to fill with 0's 
		memset(&compressed_binary[x], 0, no_bits_pad);
	}

	//Add the 1 byte length then malloc again for 
	//no. of bytes of bitcodes & extra byte(padding length)
	int compressed_pl_len = (total_space/8) + 1; 
	uint8_t* final_payload = malloc(compressed_pl_len * sizeof(uint8_t));
	int conversion[NO_BITS] = { 0 }; //temp. placeholder for reading in 8's
	final_payload[compressed_pl_len-1] = no_bits_pad; //put in padding 

	x = 0; //reusing old variable, x
	int val = 0; //what we put into the final payload from bitcodes 
	for(int i = 0; i < (total_space / 8); i++) { 
		//2 conversions needed because 16 bits(2bytes)
		for(int j = 0; j < 8; j++) { //compressed_binary
			conversion[j] = compressed_binary[x]; //copy 8 bits
			x++;
		}
		//Send to function to get decimal and put into the final payload[]
		val = get_decimal(conversion);
		final_payload[i] = val;
	}
	
	//Construct msg to send back to client:
	uint8_t* send_back = malloc((MSG_HDR_PL + compressed_pl_len) * 
		sizeof(uint8_t)); 
	uint8_t msg_header =0;

	//Set msg header type digit according to task type
	if(task == 0) { //Echo 
		msg_header = 0x10;
	}
	if(task == 2) { //Directory listing 
		msg_header = 0x30;
	}
	if(task == 4) { //File size query
		msg_header = 0x50;
	}
	if(task == 6) { //File size query
		msg_header = 0x70;
	}

	//Set compression-change 3rd bit(from right) to 1
	msg_header = msg_header | ( 1 << 3);
	send_back[0] = msg_header;

	uint64_t second_field = (uint64_t)compressed_pl_len; 
	payload_len_endian(second_field, send_back); //put length in
	for(int i = 0; i < compressed_pl_len; i++) { //Copy compressed payload in
		send_back[MSG_HDR_PL+i] = final_payload[i];
	}

	write(clientsocket_fd, send_back, (MSG_HDR_PL + compressed_pl_len));

	free(send_back); 
	free(compressed_binary);
	free(final_payload);
	return;
}

/** 
Combines the directory name with the target filename. 
Allows to access the target file.
*/
char* absolute_path(char* directory, char* fname) {
	int space = strlen(directory) + strlen(fname) + 2; //+2 for null char
	char* result = malloc(space * sizeof(char));
	
	int idx = 0; //where we insert into result array
	while(idx < strlen(directory)) {
		result[idx] = directory[idx];
		idx++;
	}
	result[idx] = '/'; //separate directory and fname
	idx++;
	
	int i = 0; //ctr for reading fname 
	while(idx < space - 1) {
		result[idx] = fname[i];
		i++;
		idx++;
	}
	result[idx] = '\0';

	return result;
}

/** 
Performs file size query.
Gets the length of the file(in bytes) from the 
target_file(if it does exist in the directory(2nd param.)
*/
void file_size_query(struct bitcodes bits_array, char* directory, 
	int clientsocket_fd, uint8_t requires_compress, uint8_t compression_bit, 
	uint8_t* payload, uint64_t payload_length) {

	char* target_file = NULL; //target file name 
	struct decompressed_info* d1 = NULL; //may be used if payload compressed

	if((int)compression_bit == 1) { //Payload has been compressed 
		d1 = decompress(payload, payload_length, bits_array);
		target_file = malloc(d1->original_payload_size * sizeof(char));
		for(int i = 0; i < d1->original_payload_size; i++) {
			target_file[i] = d1->original_payload[i];
		}
	}else{
		//Convert payload of uint8 type to char type
		target_file = malloc(payload_length * sizeof(char));
		for(int i = 0; i < payload_length; i++) {
			target_file[i] = payload[i];
		}
	}

	char* merged_fnames = absolute_path(directory, target_file); //combine 
	int fsize = 0;
	uint64_t file_size = 0; //payload field 
	
	DIR *d;
	struct dirent *dir;
	d = opendir(directory);
	bool target_found = false;
	if(d) { 
		while((dir = readdir(d)) != NULL) { //Checking for regular files
			if(dir->d_type == DT_REG){
				if(strcmp(dir->d_name, target_file) == 0) { //file exists
					target_found = true;
					FILE* f = fopen(merged_fnames, "rb");
					fseek(f, 0L, SEEK_END); 
					fsize = ftell(f); //get no. of bytes
					file_size =(uint64_t)fsize;
					fclose(f);
					break;
				}
			}
		}
	}
	closedir(d);

	//If target file doesn't exist, return error msg 
	if(!target_found) {
		send_error_msg(clientsocket_fd);
		free(merged_fnames);
		free(target_file);
		if((int)compression_bit == 1) {
			free_decompress_struct(d1);
		}
		free(payload);
		return;
	}

	//If payload needs to be compressed:
	if((int)requires_compress == 1) {
		uint8_t* payload_contents = malloc(8 * sizeof(uint8_t));

		int shift = 56; //put in file size 
		for(int idx = 0; idx < 8; idx++) {
			payload_contents[idx] = (uint8_t) ((file_size >> shift) & 0xff);
			shift = shift - 8;
		}
		compression_then_send(4, payload_contents, 8, bits_array, 
			clientsocket_fd);
		free(payload_contents);

	}else{
		//No compression needed 
		uint8_t* send_back = malloc(FILE_SIZE_BYTES * sizeof(uint8_t));
		send_back[0] = 0x50; //msg header
		memset(&send_back[1], 0, 7); //Put in 0x00 7 times
		send_back[8] = 0x8; //payload length value is 8
		puts_big_endian(file_size, send_back); //last 8 bytes in network order
		write(clientsocket_fd, send_back, FILE_SIZE_BYTES);
		free(send_back);
	}
	
	free(target_file);
	free(merged_fnames);
	if((int)compression_bit == 1) {
		free_decompress_struct(d1);
	}
	free(payload);
}

/** Frees the decompression struct member */
void free_decompress_struct(struct decompressed_info* d1) {
	free(d1->original_payload);
	free(d1);
}

/** Performs Directory Listing task */
void dir_listing(struct bitcodes bits_array, char* directory, 
	int clientsocket_fd, uint8_t requires_compress) {
	//Possible scenarios to handle:
	//1. Directory has 0 regular files
	//2. Send MSG back with compression
	//3. Send MSG back without compression

	int fname_chars = 0; //the number of characters in each filename 
	DIR *d;
	struct dirent *dir;
	d = opendir(directory);
	int number_files = 0; 
	if(d) {
		while((dir = readdir(d)) != NULL) { //Checking for regular files
			if(dir->d_type == DT_REG){
				//+1 for null byte 
				fname_chars = fname_chars+ strlen(dir->d_name) + 1;
				number_files++; 
			}
		}
	}

	if(number_files == 0) { //If directory is empty(no regular files)
		uint8_t empty_dir[EMPTY_DIR_BYTES] = {0x30, 0x00, 0x00, 0x00, 0x00, 
			0x00, 0x00, 0x00, 0x10, 0x00};
		write(clientsocket_fd, empty_dir, EMPTY_DIR_BYTES);
		return;
	}

	rewinddir(d);
	uint8_t* payload_contents = malloc(fname_chars * sizeof(uint8_t));
	//each uint8 element represents each letter in fname or 
	//the null terminating char. 

	int length_each_fn = 0;
	int ctr = 0;
	int convert = 0;
	while((dir = readdir(d)) != NULL) {
		if(dir->d_type == DT_REG){
			length_each_fn = strlen(dir->d_name);
			for(int i = 0; i <length_each_fn; i++) { //copy each char in 
				convert = (int)dir->d_name[i]; //get decimal of char
				payload_contents[ctr] = (uint8_t)convert;
				ctr++;
			}
			payload_contents[ctr] = 0; //add the nulll byte in
			ctr++;
		}
	}
	closedir(d);

	//Now have made the payload(payload_contents) and 
	//fname_chars is payload length 

	if((int)requires_compress == 1) { //need to compress the payload 
		compression_then_send(2, payload_contents, fname_chars, bits_array, 
			clientsocket_fd);
	}else{ //send as is
		int msg_length = MSG_HDR_PL + fname_chars; //fname_chars=payload len
		//The msg sent back to client 
		uint8_t* send_back = malloc(msg_length * sizeof(uint8_t)); 
		send_back[0] = 0x30;

		//Put the payload length value into 2nd field in msg
		payload_len_endian((uint64_t)fname_chars, send_back); 
		for(int i = 0; i < fname_chars; i++) { //copy payload in
			send_back[MSG_HDR_PL+i] = payload_contents[i];
		}
		write(clientsocket_fd, send_back, msg_length); //Write back to client
		free(send_back);
	}

	free(payload_contents);
	return;
}

/** 
Read the contents of compression dictionary file into the struct member 
passed in. 'bits_array' will be used in several other functions. 
*/
void read_compressed_dictionary(struct bitcodes* bits_array) {
	FILE* fp = fopen(COMPRESSION_DICT, "rb"); 
	if(fp == NULL) { //file doesn't exist
		exit(0);
	}
	fseek(fp, 0L, SEEK_END); 
	int total_bytes = ftell(fp); //get no. of bytes in file 
	fseek(fp, 0L, SEEK_SET);
	for(int i = 0; i < total_bytes; i++) { //get each byte 
		//put each byte into the array
		fread(&bits_array->each_byte[i], sizeof(uint8_t), 1, fp);
	}
	fclose(fp);

	//for conversion(to get the length). May get bits over 2 bytes 
	int temp_length_bits[NO_BITS] = {0};

	//Store current byte we are reading the length of
	//Store current bit we left off reading 
	int current_byte = 0;
	int current_bit = 0; 
	int counter = 0; //for every segment read
	int length = 0; //length=number of bits in bitcode
	int insert = 0; //idx where we insert each bit in ptr array

	while(counter < SEGMENTS) { //Read 1 segment at a time.
		//Finding the length for each bitcode
		if(current_bit + 7 > 7) {  //read length over to the next byte 
			//get no. of bits you can read in current byte
			int no_bits_current = 8 - current_bit;
			for(int i = 0; i < no_bits_current; i++) { 
				temp_length_bits[i] = ((bits_array->
					each_byte[current_byte] >> (7 - current_bit)) & 1);
				current_bit++;
			}
			//Update the byte and bit 
			current_byte++;
			current_bit = 0;
			//Get remainder of bits to read from the next byte 
			int no_bits_nextbyte = 8 - no_bits_current; 
			for(int i = 0; i < no_bits_nextbyte; i++) {
				temp_length_bits[no_bits_current+i] = ((bits_array->
					each_byte[current_byte] >> (7 - i)) & 1);
			}
			//Update the bit again
			current_bit = current_bit+no_bits_nextbyte; 
		}else{ 
			for(int i = 0; i < 8; i++) { 
				temp_length_bits[i]= ((bits_array->
					each_byte[current_byte] >> (7 - i)) & 1);
			}
			current_bit = 0;
			current_byte++;
		}
		//Extract the bitcode for this segment 
		length = get_decimal(temp_length_bits);
		//Put length of bitcode into struct 
		bits_array->length_code[counter] = length;

		//Put each bitcode into the struct 
		insert = 0;
		while(insert < length) {
			bits_array->code[counter][insert] = ((bits_array->
				each_byte[current_byte] >> (7 - current_bit)) & 1);
			//Check not going out of range & update
			if(current_bit == 7) { //onto next byte now
				current_bit = 0;
				current_byte++;
			}else{ //only update the bit
				current_bit++;
			}
			insert++;
		}
		counter++; //a segment has been read 
	}
}

/** Check if client has shutdown */
bool check_shutdown(uint8_t type_digit, uint64_t payload_length) {
	int val = (int)type_digit;
	if(val == 8 && payload_length == 0) {
		return true;
	}
	return false;
}

/** 
Used with retrieve_file() and sends msg back to client 
because the current session ID is already in use. Releases memory. 
*/
void retrieve_id_occupied(int clientsocket_fd, char* target_fname, 
	char* full_file_path) {

	uint8_t id_occupied[MSG_HDR_PL] = {0x70, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
		0x00, 0x00};
	write(clientsocket_fd, id_occupied, MSG_HDR_PL);
	free(target_fname);
	free(full_file_path);

}

/** Free heap memory used in retrieve task */
void retrieve_free_memory(uint8_t* send_back, uint8_t* payload, 
	char* target_fname, uint8_t* file_contents, char* full_file_path) {
	free(send_back);
	free(payload);
	free(target_fname);
	free(file_contents);
	free(full_file_path);
}

/** 
Used with retrieve file task. Returns True if there are errors such as 
target file not found in directory, or an invalid range(of file size)
*/
bool retrieve_detect_errors(bool target_found, bool invalid_file_range, DIR *d,
	int clientsocket_fd, char* target_fname, char* full_file_path, 
	uint8_t* payload) {

	if(!target_found || invalid_file_range) {
		closedir(d);
		send_error_msg(clientsocket_fd);
		free(target_fname);
		free(full_file_path);
		free(payload);
		return true;
	}
	return false;
}

/** 
Convert an array of 4 uint8_t elements, return a 
uint32_t as the session ID. 
Used with retrieve file task. 
*/
uint32_t get_session_id(uint8_t session_ID[SESSION_BYTES]) {
	uint32_t curr_id = session_ID[0] | (session_ID[1] << 8) | 
		(session_ID[2] << 16) | (session_ID[3] << 24);
	
	return curr_id;
}

/** 
Performs retrieval of file task. 
Sends part of the file in the payload 
*/
void retrieve_file(uint8_t* payload, uint64_t payload_length, 
	struct bitcodes bits_array, char* directory, int clientsocket_fd, uint8_t 
		compression_bit, uint8_t requires_compress, uint32_t* child_session_id) {

	if((int)compression_bit == 1) { //Check if payload has been compressed
		struct decompressed_info* d1 = decompress(payload, payload_length, 
			bits_array);

		//Get target file name from end of passed in payload 
		int fn_length = d1->original_payload_size - 20;
		char* target_fname = malloc(fn_length * sizeof(char));
		for(int i = 0; i < fn_length; i++) {
			target_fname[i] = d1->original_payload[20+i];
		}
		char* full_file_path = absolute_path(directory, target_fname);
		//Create the actual payload(to be sent to client) first 
		
		uint8_t session_ID[SESSION_BYTES]; //Get session ID
		memcpy(&session_ID, d1->original_payload, SESSION_BYTES);
		//Convert session id to uint32_t
		uint32_t curr_id = get_session_id(session_ID);

		if(*child_session_id == curr_id) {
			retrieve_id_occupied(clientsocket_fd, target_fname, full_file_path);
			free_decompress_struct(d1);
			return;
		}
		*child_session_id = curr_id; //Set session ID as in-use
		
		//Extract starting offset and Number of bytes to read from file
		uint8_t start_offset[NO_BITS]; //read in reverse order 
		uint8_t length_data[NO_BITS]; //read in reverse order 
		for(int i = 0; i < 8; i++) {
			start_offset[7-i] = d1->original_payload[4+i]; 
			length_data[7-i] = d1->original_payload[12+i]; 
		}
		//Get integer of these 2 fields 
		uint64_t start_reading_from = *((int64_t*)start_offset);
		uint64_t read_range = *((int64_t*)length_data);
		uint8_t* file_contents; //put file contents in here 
		
		DIR *d;
		struct dirent *dir;
		d = opendir(directory);
		bool target_found = false;
		bool invalid_file_range = false;
		
		int fsize = 0;
		while((dir = readdir(d)) != NULL) {
			if(dir->d_type == DT_REG){ //Checking for regular files
				if(strcmp(dir->d_name, target_fname) == 0) {
					target_found = true;
					FILE* f = fopen(full_file_path, "rb");
					fseek(f, 0L, SEEK_END); 
					fsize = ftell(f); //get no. of bytes
					//Check if invalid range:
					if((int)start_reading_from + (int)read_range > fsize) {
						invalid_file_range = true;
					}
					if(!invalid_file_range) { //read and get from file 
						//where to store the file contents 
						file_contents = malloc(((int)read_range)* 
							sizeof(char));
						fseek(f, 0L, SEEK_SET); //Put fp back to start of file
						fseek(f, (int)start_reading_from, SEEK_CUR);
						fread(file_contents, sizeof(uint8_t), 
							(int)read_range, f);
					}
					fclose(f);
					break;
				}
			}
		}

		//Check for errors: 
		if(retrieve_detect_errors(target_found, invalid_file_range, d, 
			clientsocket_fd, target_fname, full_file_path, payload)) {
			free_decompress_struct(d1);
			return;
		}
		closedir(d);
		
		uint8_t* send_back = NULL; //what to send back to client 

		//Decompression and need to compress
		if((int)requires_compress == 1) {
			//Only get payload 
			int payload_len = 20 + read_range;
			send_back = malloc(payload_len * sizeof(uint8_t)); //payload
			//Copy the first 20bytes of payload from original 
			for(int i = 0; i < 20; i++) {
				send_back[i] = d1->original_payload[i];
			}
			for(int i = 0; i < read_range; i++) { //Copy the file contents 
				send_back[20+i] = file_contents[i];
			}
			compression_then_send(6, send_back, payload_len, bits_array, 
				clientsocket_fd);
		}else{
			//Decompression and no need to compress
			int payload_len = 20 + read_range;
			int msg_length = MSG_HDR_PL + (20 + read_range);
			
			send_back = malloc(msg_length * sizeof(uint8_t));
			send_back[0] = 0x70;
			payload_len_endian(payload_len, send_back); //Put in payload length 
			//Copy the first 20bytes of payload from original 
			for(int i = 0; i < 20; i++) {
				send_back[MSG_HDR_PL+i] = d1->original_payload[i]; 
			}
			//Copy the file contents 
			for(int i = 0; i < read_range; i++) {
				send_back[29+i] = file_contents[i];
			}
			write(clientsocket_fd, send_back, msg_length);
		}

		retrieve_free_memory(send_back, payload, target_fname, file_contents, 
			full_file_path);
		free_decompress_struct(d1);

	}else{ //Payload is not compressed 
		int fn_length = payload_length - 20;
		char* target_fname = malloc(fn_length* sizeof(char));
		//Get target fname from end of payload 
		for(int i = 0; i < fn_length; i++) {
			target_fname[i] = payload[20+i];
		}
		char* full_file_path = absolute_path(directory, target_fname);
		
		uint8_t session_ID[SESSION_BYTES]; //Get session ID 
		memcpy(&session_ID, payload, SESSION_BYTES);

		uint32_t curr_id = get_session_id(session_ID);
			
		if(*child_session_id == curr_id) { //check error 
			retrieve_id_occupied(clientsocket_fd, target_fname, full_file_path);
			return;
		}
		*child_session_id = curr_id; //Set session ID as in-use
		
		//Extract starting offset and Number of bytes to read from file
		uint8_t start_offset[NO_BITS]; //read in reverse order 
		uint8_t length_data[NO_BITS]; //read in reverse order 
		for(int i = 0; i < 8; i++) {
			start_offset[7-i] = payload[4+i];
			length_data[7-i] = payload[12+i]; 
		}
		//Get integer of these 2 fields 
		uint64_t start_reading_from = *((int64_t*)start_offset);
		uint64_t read_range = *((int64_t*)length_data);
		uint8_t* file_contents; //put file contents in here 
		
		DIR *d;
		struct dirent *dir;
		d = opendir(directory);
		bool target_found = false;
		bool invalid_file_range = false;
		
		int fsize = 0;
		while((dir = readdir(d)) != NULL) { //Checking for regular files
			if(dir->d_type == DT_REG){
				if(strcmp(dir->d_name, target_fname) == 0)  { //file exists
					target_found = true;
					FILE* f = fopen(full_file_path, "rb");
					fseek(f, 0L, SEEK_END); 
					fsize = ftell(f); //get no. of bytes

					if((int)start_reading_from + (int)read_range > fsize) {
						invalid_file_range = true;
					}
					if(!invalid_file_range) { //read and get from file 
						file_contents = malloc(((int)read_range)* sizeof(char));
						fseek(f, 0L, SEEK_SET); //Put fp back to start of file
						fseek(f, (int)start_reading_from, SEEK_CUR);
						fread(file_contents, sizeof(uint8_t), (int)read_range, f);
					}
					fclose(f);
					break;
				}
			}
		}

		if(retrieve_detect_errors(target_found, invalid_file_range, d, 
			clientsocket_fd, target_fname, full_file_path, payload)) {
			return;
		}
		closedir(d);
		uint8_t* send_back;

		//Contents from file already stored in file_contents*
		if((int)requires_compress == 0) { //Compression not needed
			int payload_len = 20 + read_range;
			int msg_length = MSG_HDR_PL + (20 + read_range); //payload
			send_back = malloc(msg_length * sizeof(uint8_t));
			send_back[0] = 0x70;
			payload_len_endian(payload_len, send_back);  
			for(int i = 0; i < 20; i++) {
				send_back[MSG_HDR_PL+i] = payload[i];
			}
			for(int i = 0; i < read_range; i++) { //Copy the file contents 
				send_back[29+i] = file_contents[i];
			}
			write(clientsocket_fd, send_back, msg_length);
		}else{ //Compression required 
			int payload_len = 20 + read_range; //Only get payload 
			send_back = malloc(payload_len* sizeof(uint8_t));
			for(int i = 0; i < 20; i++) { //get 1st 20 bytes of PL from original
				send_back[i] = payload[i];
			}
			for(int i = 0; i < read_range; i++) { //Copy the file contents 
				send_back[20+i] = file_contents[i];
			}
			compression_then_send(6, send_back, payload_len, bits_array, 
				clientsocket_fd);
		}
		retrieve_free_memory(send_back, payload, target_fname, file_contents, 
			full_file_path);
	}
	return;
}


/** 
Checks if Type Digit is valid or not. 
Return True if so.
*/
bool check_valid_type(uint8_t type_digit) {
	int val = (int)type_digit;
	if(val == 0 || val == 2 || val == 4 || val == 6 ) {
		return true;
	}
	return false;
}

/** Network connection setup */
void setup_network(int serversocket_fd, in_addr_t ip_addr, 
	uint16_t port_number, struct sockaddr_in address) {
	int option = 1;

	//identifies the address family or format of the socket address
	address.sin_family = AF_INET; 
	address.sin_addr.s_addr = ip_addr; //IP address of server
	address.sin_port = port_number; //server port

	setsockopt(serversocket_fd, SOL_SOCKET, SO_REUSEADDR | 
		SO_REUSEPORT, &option, sizeof(int)); //reuse the port and addresss
	if(bind(serversocket_fd, (struct sockaddr*)&address, 
		sizeof(struct sockaddr_in))) {
		exit(1);
	}

	//Listen for clients trying to connect to server &
	//queue incoming connection requests if not accepting 
	listen(serversocket_fd, LISTEN_BACKLOG); 
	return;
}

/** Performs the echo request. */
void echo_task(uint8_t buffer[MSG_HDR_PL], struct bitcodes bits_array, 
	int clientsocket_fd, uint8_t* payload, uint64_t payload_length, 
	uint8_t compression_bit, uint8_t requires_compress) {

	if((int)compression_bit == 1) { //Payload is compressed 

		uint8_t* send_back = NULL; //what server sends back to client 

		if((int)requires_compress == 1) {
			//Just copy from original 
			int total = MSG_HDR_PL + payload_length; //Calculate total bytes
			send_back = malloc(total * sizeof(uint8_t));
			uint8_t msg_header = 0x10;
			msg_header = msg_header | ( 1 << 3); //set compressed bit 
			send_back[0] = msg_header;
			payload_len_endian(payload_length, send_back); //Copy PL length 
			for(int i = 0; i < payload_length; i++) { //Copy same PL
				send_back[MSG_HDR_PL+i] = payload[i];
			}
			payload_len_endian(payload_length, send_back); //Copy PL length
			write(clientsocket_fd, send_back, total); //send back to client
		}else{ //Decompressed payload but don't need to compress
			struct decompressed_info* d1 = decompress(payload, 
				payload_length, bits_array);

			int total= MSG_HDR_PL + d1->original_payload_size; //total bytes
			send_back = malloc(total* sizeof(uint8_t));
			send_back[0] = 0x10; //msg header
			payload_len_endian(d1->original_payload_size, send_back); 
			for(int i = 0; i < d1->original_payload_size; i++) { 
				send_back[MSG_HDR_PL+i] = d1->original_payload[i];
			}
			write(clientsocket_fd, send_back, total);
			free_decompress_struct(d1);
		}

		free(send_back);

	}else{ //Payload is not compressed 
		if((int)requires_compress == 1) {
			compression_then_send(0, payload, payload_length,
				bits_array, clientsocket_fd);
		}else{
			int total = MSG_HDR_PL + payload_length; //Calculate total bytes
			uint8_t* send_back = malloc(total* sizeof(uint8_t));
			send_back[0] = 0x10; 
			payload_len_endian(payload_length, send_back); //Copy length 
			for(int i = 0; i < payload_length; i++) { //Copy same PL 
				send_back[MSG_HDR_PL+i] = payload[i];
			}
			write(clientsocket_fd, send_back, total); //send back to client
			free(send_back);
		}
	}

	free(payload); 
	return;
}

int main(int argc, char** argv) {

	FILE* fp = fopen(argv[1], "rb");
	if(fp == NULL) { //file doesn't exist
		exit(1);
	}
	fseek(fp, 0L, SEEK_END); 
	int fn_total_bytes = ftell(fp); //get no. of bytes in config file
	fn_total_bytes = fn_total_bytes - CONFIG_IP_PORT; //no. of bytes for fname

	uint16_t port_number = 0; 
	in_addr_t ip_addr; //host interface address in network byte order
	char* target_directory = malloc((fn_total_bytes + 1) * sizeof(char));
	
	fseek(fp, 0L, SEEK_SET); //Put fp back to start of file
	fread(&ip_addr, sizeof(int), 1, fp); //get address
	fread(&port_number, sizeof(uint16_t), 1, fp); //get port number
	//get target file directory
	fread(target_directory, sizeof(char), fn_total_bytes, fp); 
	target_directory[fn_total_bytes] = '\0'; //add null byte 
	fclose(fp); 

	struct bitcodes bits_array; //used to store the compressed dict. contents
	read_compressed_dictionary(&bits_array); //read dictionary and store

	//Create socket id->socket(int domain, int type, int protocol)
	int serversocket_fd = -1;
	int clientsocket_fd = -1;
	serversocket_fd = socket(AF_INET, SOCK_STREAM, 0); //SOCK_STREAM=TCP
	if(serversocket_fd < 0) { //check
		exit(1);
	}
	struct sockaddr_in address; //data type for server socket address
	//Call network connection function
	setup_network(serversocket_fd, ip_addr, port_number, address); 

	//Allow all child processes to read the sessionID in retrieve file task. 
	uint32_t* child_session_id = mmap(NULL, SESSION_BYTES, PROT_READ | 
		PROT_WRITE, MAP_SHARED | MAP_ANONYMOUS, -1, 0);

	//make the server continually listen for incoming connections/clients
	while(1) { 
		uint32_t addrlen = sizeof(struct sockaddr_in);
		clientsocket_fd = accept(serversocket_fd, (struct sockaddr*)&address, 
			&addrlen);

		pid_t p = fork();
		if(p == 0) { //in child process
			while(1) {

				uint8_t buffer[MSG_HDR_PL]; //stores msg header & payload length
				memset(buffer, 0, MSG_HDR_PL); //initialise with 0 bytes 
				uint8_t payload_hex[NO_BITS]; //hex bytes of payload length
				uint8_t msg_header = 0;
				uint8_t type_digit = 0;
				uint8_t compression_bit = 0; 
				uint8_t requires_compress = 0;
				uint8_t padding = 0;
				uint64_t payload_length = 0;
				uint8_t* payload = NULL;; //malloc later after error checking
		
				ssize_t ret_val = 0; //read from CLIENT socket 
				//get msg header and length
				ret_val = recv(clientsocket_fd, buffer, MSG_HDR_PL, 0); 
				if(ret_val <= 0) { //check no data read/client has shutdown
					break;
				}

				msg_header = buffer[0]; //get the 1st byte
				for(int i = 0; i < 8; i++) { //copy hex values in reverse order
					payload_hex[7-i] = buffer[1+i];
				}
				payload_length = *((int64_t*)payload_hex);
				type_digit = msg_header >> 4; //Get 1st 4 bits from msg header
				compression_bit = ((msg_header >> 3) & 1); //4th bit from right
				requires_compress = ((msg_header >> 2)  & 1); //3rd from right
				padding = ((msg_header >> 0) & ((1 << 2) - 1)); //lower 2 bits 

				if(check_shutdown(type_digit, payload_length)) { 
					perform_shutdown(clientsocket_fd, serversocket_fd);
					exit(0); 
				}

				//Check for ERROR functionality(invalid types)
				if((!check_valid_type(type_digit)) || padding != 0) {
					send_error_msg(clientsocket_fd);
					break;
				}

				//Can assume valid functionality now
				int task_no = (unsigned int)type_digit; //0,2,4,6
				//Ignore Directory Listing(because no payload sent in msg)
				if(task_no == 0 || task_no == 4 || task_no == 6) {
					//Setup space for payload & Get payload
					payload = malloc(payload_length * sizeof(uint8_t));
					ret_val = recv(clientsocket_fd, payload, payload_length, 0);
					if(ret_val <= 0) { //checking for error
						free(payload);
						break;
					}
				}

				//Main 4 tasks
				if(task_no == 0) { //Checking for echo
					echo_task(buffer, bits_array, clientsocket_fd, payload, 
						payload_length, compression_bit, requires_compress);

				}else if(task_no == 2) { //Check for dir listing
					dir_listing(bits_array, target_directory, clientsocket_fd,
						requires_compress);
				}else if(task_no == 4) { //Check for file size query 
					file_size_query(bits_array, target_directory, 
						clientsocket_fd, requires_compress, 
						compression_bit, payload, payload_length);
					
				}else{ //Retrieve file functionality
					retrieve_file(payload, payload_length, bits_array, 
						target_directory, clientsocket_fd, compression_bit, 
						requires_compress, child_session_id);
				}
			}

			//Cleanups and exits 
			free(target_directory);
			close(clientsocket_fd);
			exit(0);
		}
	}

	free(target_directory);
	shutdown(serversocket_fd, SHUT_RDWR);
	close(serversocket_fd);
	return 0;
}
