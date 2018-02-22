#include <cstdlib>
#include <string>
#include <iostream>
#include <xmlrpc-c/girerr.hpp>
#include <xmlrpc-c/base.hpp>
#include <xmlrpc-c/client_simple.hpp>
#include <pbc/pbc.h>
#include <iostream>
#include <fstream>
#include <PBC/Pairing.h>
#include <PBC/G1.h>
#include "systemparam.h"

using namespace std;

static int is_base64(char c) {
	if ((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z')
			|| (c >= '0' && c <= '9') || (c == '+') || (c == '/')
			|| (c == '=')) {
		return 1;
	}
	return 0;
}

static unsigned char decode_base64_char(char c) {
	if (c >= 'A' && c <= 'Z')
		return (c - 'A');
	if (c >= 'a' && c <= 'z')
		return (c - 'a' + 26);
	if (c >= '0' && c <= '9')
		return (c - '0' + 52);
	if (c == '+')
		return 62;
	return 63;
}

static char encode_base64_char(unsigned char u) {
	if (u < 26)
		return 'A' + u;
	if (u < 52)
		return 'a' + (u - 26);
	if (u < 62)
		return '0' + (u - 52);
	if (u == 62)
		return '+';
	return '/';
}

unsigned char* decode64(const std::string string, int* ndata) {
	const char* src = string.c_str();
	int length = string.length();
	if (!length) {
		*ndata = 0;
		return NULL;
	}
	unsigned char *dest = NULL;
	if (src && *src) {
		dest = (unsigned char *) calloc(length, sizeof(char));
		unsigned char *p = dest;
		int k, l = length + 1;
		unsigned char *buf = (unsigned char*) malloc(l);
		/* Ignore non base64 chars as per the POSIX standard */
		for (k = 0, l = 0; src[k]; k++) {
			if (is_base64(src[k])) {
				buf[l++] = src[k];
			}
		}
		for (k = 0; k < l; k += 4) {
			char c1 = 'A', c2 = 'A', c3 = 'A', c4 = 'A';
			unsigned char b1 = 0, b2 = 0, b3 = 0, b4 = 0;
			c1 = buf[k];
			if (k + 1 < l) {
				c2 = buf[k + 1];
			}
			if (k + 2 < l) {
				c3 = buf[k + 2];
			}
			if (k + 3 < l) {
				c4 = buf[k + 3];
			}
			b1 = decode_base64_char(c1);
			b2 = decode_base64_char(c2);
			b3 = decode_base64_char(c3);
			b4 = decode_base64_char(c4);
			*p++ = ((b1 << 2) | (b2 >> 4));
			if (c3 != '=') {
				*p++ = (((b2 & 0xf) << 4) | (b3 >> 2));
			}
			if (c4 != '=') {
				*p++ = (((b3 & 0x3) << 6) | b4);
			}
		}
		if (buf)
			free(buf);
		*ndata = p - dest;
		return dest;
	}
	return NULL;
}

std::string encode64(const unsigned char* src, int size) {
	int i;
	char *out = NULL;
	char *p = NULL;
	if (!src)
		return "";
	if (!size)
		return "";

	out = (char *) calloc(size * 4 / 3 + 4, sizeof(char));
	p = out;
	for (i = 0; i < size; i += 3) {
		unsigned char b1 = 0, b2 = 0, b3 = 0, b4 = 0, b5 = 0, b6 = 0, b7 = 0;
		b1 = src[i];
		if (i + 1 < size)
			b2 = src[i + 1];
		if (i + 2 < size)
			b3 = src[i + 2];
		b4 = b1 >> 2;
		b5 = ((b1 & 0x3) << 4) | (b2 >> 4);
		b6 = ((b2 & 0xf) << 2) | (b3 >> 6);
		b7 = b3 & 0x3f;
		*p++ = encode_base64_char(b4);
		*p++ = encode_base64_char(b5);
		if (i + 1 < size) {
			*p++ = encode_base64_char(b6);
		} else {
			*p++ = '=';
		}
		if (i + 2 < size) {
			*p++ = encode_base64_char(b7);
		} else {
			*p++ = '=';
		}
	}
	std::string ret = std::string(out);
	free(out);
	return ret;
}

int main(int argc, char **) {

    if (argc-1 > 0) {
        cerr << "This program has no arguments" << endl;
        exit(1);
    }

    try {
        string const serverUrl("http://localhost:8080/RPC2");
        string const methodName("sample.authenticate");

        xmlrpc_c::clientSimple myClient;
        xmlrpc_c::value result;

        myClient.call(serverUrl, methodName, "sss", &result, "rick", "123456", "artigo/group1/1.0");

        //unsigned char *share = xmlrpc_c::value_bytestring(result);
        string ret = xmlrpc_c::value_string(result);
        int ndata;
        unsigned char *decoded_share;

        decoded_share = decode64(ret, &ndata);

        element_t e_priv;

        FILE * pFile;
        	long lSize;
        	char * buffer;
        	size_t result2;

        	pFile = fopen("pairing.param", "r");
        	if (pFile == NULL) {
        		fputs("File error", stderr);
        		exit(1);
        	}

        	// obtain file size:
        	fseek(pFile, 0, SEEK_END);
        	lSize = ftell(pFile);
        	rewind(pFile);

        	// allocate memory to contain the whole file:
        	buffer = (char*) malloc(sizeof(char) * lSize);
        	if (buffer == NULL) {
        		fputs("Memory error", stderr);
        		exit(2);
        	}

        	// copy the file into the buffer:
        	result2 = fread(buffer, 1, lSize, pFile);
        	fclose(pFile);

        	if (!result2)
        		pbc_die("input error");

        SystemParam sysparam("pairing.param", "system.param");

        const Pairing& e = sysparam.get_Pairing();

        pairing_t pairing;


        pairing_init_set_buf(pairing, buffer, result2);
        element_init_G1(e_priv, pairing);

        element_from_bytes(e_priv, decoded_share);



        //G1 priv;

        //priv = G1(e, decoded_share, ndata, false, 10);

        FILE *f_priv;
        f_priv = fopen("shares/priv1", "w");

        //priv.dump(f_priv, "priv1", 10);
        element_out_str(f_priv, 10, e_priv);

        fclose(f_priv);
//
//
//
//        ofstream f_privkey;
//        f_privkey.open("shares/privke1");
//        f_privkey.write(ret.c_str(), ret.size());
//        f_privkey.close();

        cout << ret << endl;

    } catch (exception const& e) {
        cerr << "Client threw error: " << e.what() << endl;
    } catch (...) {
        cerr << "Client threw unexpected error." << endl;
    }

    return 0;
}
