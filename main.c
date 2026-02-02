#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include <curl/curl.h>
#include <openssl/hmac.h>
#include <openssl/sha.h>

#define REGION "us-east-1"
#define SERVICE "s3"

const char *access_key = "AKIAAAAAAAAAAAAAAAAA";
const char *secret_key = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const char *bucket	   = "bucket-name";
const char *object	   = "test.bin";
const char *endpoint   = "https://bucket-name.s3.us-east-1.amazonaws.com";
const char *filename   = "test.bin";

static void hex(const unsigned char *in, size_t len, char *out) {
	static const char *h = "0123456789abcdef";
	for (size_t i = 0; i < len; i++) {
		out[i*2]	 = h[in[i] >> 4];
		out[i*2 + 1] = h[in[i] & 0x0f];
	}
	out[len*2] = 0;
}

static void sha256_hex(const void *data, size_t len, char out[65]) {
	unsigned char hash[32];
	SHA256(data, len, hash);
	hex(hash, 32, out);
}

static void hmac_sha256(const unsigned char *key, size_t keylen, const char *data, unsigned char out[32]) {
	unsigned int len = 32;
	HMAC(EVP_sha256(), key, keylen, (const unsigned char*)data, strlen(data), out, &len);
}

char *read_file(const char *filename, size_t *out_size) {
	FILE *f = fopen(filename, "rb");
	if (!f) return NULL;

	fseek(f, 0, SEEK_END);
	long size = ftell(f);
	rewind(f);

	char *buffer = malloc(size);
	if (!buffer) {
		fclose(f);
		return NULL;
	}

	fread(buffer, 1, size, f);
	fclose(f);

	*out_size = size;
	return buffer;
}

int main(void) {
	size_t payload_len;
	const unsigned char *payload = read_file(filename, &payload_len);
	/* const unsigned char payload[] = "hello s3\n"; */
	/* size_t payload_len = sizeof(payload) - 1; */

	time_t t = time(NULL);
	struct tm *gmt = gmtime(&t);

	char amz_date[17];
	char date[9];
	strftime(amz_date, sizeof(amz_date), "%Y%m%dT%H%M%SZ", gmt);
	strftime(date, sizeof(date), "%Y%m%d", gmt);

	char payload_hash[65];
	sha256_hex(payload, payload_len, payload_hash);

	char canonical[2048];
	snprintf(canonical,
             sizeof(canonical),
             "PUT\n"
             "/%s\n"
             "\n"
             "host:%s.s3.%s.amazonaws.com\n"
             "x-amz-content-sha256:%s\n"
             "x-amz-date:%s\n"
             "\n"
             "host;x-amz-content-sha256;x-amz-date\n"
             "%s",
             object,
             bucket, REGION,
             payload_hash,
             amz_date,
             payload_hash);

	char canonical_hash[65];
	sha256_hex(canonical, strlen(canonical), canonical_hash);

	char string_to_sign[1024];
	snprintf(string_to_sign,
             sizeof(string_to_sign),
             "AWS4-HMAC-SHA256\n"
             "%s\n"
             "%s/%s/%s/aws4_request\n"
             "%s",
             amz_date,
             date, REGION, SERVICE,
             canonical_hash);

	unsigned char k_date[32], k_region[32], k_service[32], k_signing[32];
	char key0[128];
	snprintf(key0, sizeof(key0), "AWS4%s", secret_key);

	hmac_sha256((unsigned char*)key0, strlen(key0), date, k_date);
	hmac_sha256(k_date, 32, REGION, k_region);
	hmac_sha256(k_region, 32, SERVICE, k_service);
	hmac_sha256(k_service, 32, "aws4_request", k_signing);

	unsigned char sig_bin[32];
	hmac_sha256(k_signing, 32, string_to_sign, sig_bin);

	char signature[65];
	hex(sig_bin, 32, signature);

	char auth[1024];
	snprintf(auth,
             sizeof(auth),
             "Authorization: AWS4-HMAC-SHA256 "
             "Credential=%s/%s/%s/%s/aws4_request, "
             "SignedHeaders=host;x-amz-content-sha256;x-amz-date, "
             "Signature=%s",
             access_key,
             date, REGION, SERVICE,
             signature);

	CURL *curl = curl_easy_init();
	if (!curl) return 1;

	struct curl_slist *hdrs = NULL;
	char h1[128], h2[128];
	snprintf(h1, sizeof(h1), "x-amz-date: %s", amz_date);
	snprintf(h2, sizeof(h2), "x-amz-content-sha256: %s", payload_hash);

	hdrs = curl_slist_append(hdrs, h1);
	hdrs = curl_slist_append(hdrs, h2);
	hdrs = curl_slist_append(hdrs, auth);

	char url[1024];
	snprintf(url, sizeof(url), "%s/%s", endpoint, object);

	curl_easy_setopt(curl, CURLOPT_URL, url);
	curl_easy_setopt(curl, CURLOPT_HTTPHEADER, hdrs);
	curl_easy_setopt(curl, CURLOPT_CUSTOMREQUEST, "PUT");
	curl_easy_setopt(curl, CURLOPT_POSTFIELDS, payload);

	curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE, payload_len);

	CURLcode res = curl_easy_perform(curl);
	if (res != CURLE_OK) {
		fprintf(stderr, "curl error: %s\n", curl_easy_strerror(res));
	}

	curl_easy_cleanup(curl);
	curl_slist_free_all(hdrs);
	return res != CURLE_OK;
}
