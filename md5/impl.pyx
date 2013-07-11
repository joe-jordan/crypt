from libc.stdlib cimport malloc, free

cdef extern from "reference.h":
    void reference_md5(unsigned char *initial_msg, size_t initial_len, unsigned char *digest)    

def reference_implementation(input):
    py_byte_input = input.encode('UTF-8')
    cdef char* unpadded_input = py_byte_input
    cdef size_t ilen
    cdef unsigned char result[16]
    
    ilen = len(py_byte_input)
    
    reference_md5(<unsigned char*>unpadded_input, ilen, result)
    
    return ''.join(['%x' % result[i] for i in range(16)])
    
    

cdef char* pad_input(char* unpadded_input, long int unpadded_byte_length, long int* output_length_in_chars):
    # compute the padded length:
    cdef long int padded_bit_length = (unpadded_byte_length * 8 + 65)
    padded_bit_length += padded_bit_length % 512

    assert padded_bit_length % 512 == 0
    
    # allocate dynamic RAM for the input string:
    cdef long int total_char_length = padded_bit_length / 8
    assert (total_char_length - unpadded_byte_length) <= 512
    cdef char* padded_input = <char*>malloc(sizeof(char) * total_char_length)
    
    # zero all the new RAM:
    cdef long int i
    for 0 <= i < total_char_length:
        padded_input[i] = 0
    
    # copy the buffer into the new memory:
    for 0 <= i < unpadded_byte_length:
        padded_input[i] = unpadded_input[i]
    
    # append the 1-bit:
    i = unpadded_byte_length
    # signed chars, so 0x80 = -127.
    padded_input[i] = -127
    
    # append the length as 64-bit int, lower bytes first.
    (<int*>padded_input)[total_char_length / 4 - 2] = <int>((unpadded_byte_length * 8) % 4294967296)
    (<int*>padded_input)[total_char_length / 4 - 1] = <int>((unpadded_byte_length * 8) / 4294967296)
    
    # set the output argument
    output_length_in_chars[0] = total_char_length
    
    return padded_input

def md5(input):
    # first, we convert the input to appropriately padded bytes:
    py_byte_input = input.encode('UTF-8')
    cdef char* unpadded_input = py_byte_input
    
    cdef long int padded_length
    cdef char* padded_input = pad_input(unpadded_input, <long int>len(py_byte_input), &padded_length)
    
    
    
    # free our manually allocated padded input string:
    free(padded_input)
