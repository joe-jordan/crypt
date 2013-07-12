from libc.stdlib cimport malloc, free

cdef extern from "reference.h":
    void reference_md5(unsigned char *initial_msg, size_t initial_len, unsigned char *digest)   

cdef extern from "my_md5.h":
    void c_md5(unsigned char* msg, long initial_len, unsigned char* digest) 

def reference_implementation(input):
    py_byte_input = input.encode('UTF-8')
    cdef char* unpadded_input = py_byte_input
    cdef size_t ilen
    cdef unsigned char result[16]
    
    ilen = len(py_byte_input)
    
    reference_md5(<unsigned char*>unpadded_input, ilen, result)
    
    return ''.join(['%02x' % result[i] for i in range(16)])


def md5(input):
    py_byte_input = input.encode('UTF-8')
    cdef char* unpadded_input = py_byte_input
    cdef long ilen
    cdef unsigned char result[16]
    
    ilen = len(py_byte_input)
    
    c_md5(<unsigned char*>unpadded_input, ilen, result)
    
    return ''.join(['%02x' % result[i] for i in range(16)])
    
