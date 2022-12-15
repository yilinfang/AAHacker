#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <memory.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>

#include <openssl/rsa.h>
#include <openssl/crypto.h>
#include <openssl/x509.h>
#include <openssl/pem.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <vector>
#include <condition_variable>
#include <cstdint>
#include <deque>
#include <functional>
#include <memory>
#include <mutex>

#include "handshake_packets.h"
#include "Message.h"
#include "enums.h"
#include "utils.h"
#include "assert.h"

/* define HOME to be dir for key and cert files... */
#define HOME "./ssl_pems/"
/* Make these what you want for cert & key files */
#define CERTF HOME "test_cert.pem"
#define KEYF HOME "test_pri.pem"
#define DHPARAM_FILE HOME "dhparam.pem"

#define CHK_NULL(x)  \
	if ((x) == NULL) \
	exit(1)
#define CHK_ERR(err, s) \
	if ((err) == -1)    \
	{                   \
		perror(s);      \
		exit(1);        \
	}
#define CHK_SSL(err)                 \
	if ((err) == -1)                 \
	{                                \
		ERR_print_errors_fp(stderr); \
		exit(2);                     \
	}

SSL_CTX *ctx = nullptr;
SSL *ssl = nullptr;
BIO *readBio = nullptr;
BIO *writeBio = nullptr;
int sd;

std::deque<Message> sendQueue;
ssize_t sendMessage(uint8_t channel, uint8_t flags,
					const std::vector<uint8_t> &buf, void *buffer, ssize_t nbytes);

// void do_handshake(int fd)
// {
//   char comm_buf[0x1000] = {0};
//   int ll = read(fd, comm_buf, 10);
//   printf("len: %d, content: ", ll);
//   for (int x = 0; x < 10; x++)
//   {
//     printf("%2x ", comm_buf[x]);
//   }
//   printf("\n");
//   send(fd, packet0, sizeof(packet0) - 1, 0);
//   puts("first packet sent!");

//   ll = recv(fd, comm_buf, 245, 0);
//   printf("len: %d, content: ", ll);
//   for (int i = 0; i < 245; i++)
//   {
//     printf("%2x ", comm_buf[i] & 0xff);
//   }
//   printf("\n");

//   send(fd, packet1, sizeof(packet1) - 1, 0);
//   puts("second packet sent!");

//   ll = recv(fd, comm_buf, 68, 0);
//   printf("len: %d, content: ", ll);
//   for (int i = 0; i < 1225; i++)
//   {
//     printf("%2x ", comm_buf[i] & 0xff);
//   }
//   printf("\n");
// }

void handleVersionReq(int sd)
{
	char comm_buf[0x1000] = {0};
	int ll = recv(sd, comm_buf, 10, 0);
	printf("len: %d, content: ", ll);
	for (int x = 0; x < 10; x++)
	{
		printf("%2x ", comm_buf[x]);
	}
	printf("\n");
	send(sd, packet0, sizeof(packet0) - 1, 0);
	puts("version check packet sent!");
}

int verifyCertificate(int preverify_ok,
					  X509_STORE_CTX *x509_ctx)
{
	return 1;
}

void initializeSsl()
{
	if (ssl)
	{
		return;
	}
	ssl = SSL_new(ctx);
	SSL_set_accept_state(ssl);
	readBio = BIO_new(BIO_s_mem());
	writeBio = BIO_new(BIO_s_mem());
	SSL_set_bio(ssl, readBio, writeBio);
}

// 这个用于初始化SSL参数
void initializeSslContext()
{
	SSL_load_error_strings();
	OpenSSL_add_ssl_algorithms();
	// const SSL_METHOD *method = SSLv23_server_method();
	const SSL_METHOD *method = TLSv1_2_server_method();

	ctx = SSL_CTX_new(method);
	if (!ctx)
	{
		exit(1);
	}

	SSL_CTX_set_ecdh_auto(ctx, 1);
	if (SSL_CTX_use_certificate_file(ctx, CERTF, SSL_FILETYPE_PEM) <= 0)
	{
		exit(2);
	}

	if (SSL_CTX_use_PrivateKey_file(ctx, KEYF, SSL_FILETYPE_PEM) <= 0)
	{
		exit(3);
	}

	DH *dh_2048 = NULL;
	FILE *paramfile = fopen(DHPARAM_FILE, "r");
	if (paramfile)
	{
		dh_2048 = PEM_read_DHparams(paramfile, NULL, NULL, NULL);
		fclose(paramfile);
	}
	else
	{
		exit(4);
	}
	if (dh_2048 == NULL)
	{
		exit(5);
	}
	if (SSL_CTX_set_tmp_dh(ctx, dh_2048) != 1)
	{
		exit(6);
	}
	SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, &verifyCertificate);
	SSL_CTX_set_options(ctx, SSL_OP_NO_TLSv1_3);
}

// 进行SSL握手
void handleSslHandshake(const void *buf, size_t nbytes)
{
	// initializeSsl();
	// BIO_write(readBio, buf, nbytes);

	auto ret = SSL_accept(ssl);
	if (ret == -1)
	{
		auto error = SSL_get_error(ssl, ret);
		if (error != SSL_ERROR_WANT_READ)
			exit(7);
		if (error == SSL_ERROR_WANT_READ)
		{
			printf("ssl want read more!\n");
		}
	}

	std::vector<uint8_t> msg;
	pushBackInt16(msg, MessageType::SslHandshake);
	auto bufferSize = 0x3000;
	char buffer[bufferSize];
	int len;
	while ((len = BIO_read(writeBio, buffer, bufferSize)) != -1)
	{
		std::copy(buffer, buffer + len, std::back_inserter(msg));
	}
	int msg_len = sendMessage(0, EncryptionType::Plain | FrameType::Bulk, msg, buffer, bufferSize);
	printf("ssl handshake packet len: %d\n", msg_len);
	send(sd, buffer, msg_len, 0);
}

// buf中存的是待加密的内容，buffer存储的是加密后的报文（在AACS中被认为可以直接发送的报文），nbytes为缓冲区buffer大小
ssize_t sendMessage(uint8_t channel, uint8_t flags,
					const std::vector<uint8_t> &buf, void *buffer, ssize_t nbytes)
{
	Message msg;
	msg.channel = channel;
	msg.flags = flags;
	msg.content = buf;

	// it should work up to about 16k, but we might get some weird hardware issues
	int maxSize = 2000;

	uint32_t totalLength = msg.content.size();
	std::vector<uint8_t> msgBytes;
	if (msg.flags & EncryptionType::Encrypted)
	{
		msgBytes.push_back(msg.channel);
		auto flags = msg.flags;
		std::vector<uint8_t>::iterator contentBegin;
		std::vector<uint8_t>::iterator contentEnd;
		// full frame
		if (msg.content.size() - msg.offset <= maxSize &&
			(flags & FrameType::Bulk))
		{
			contentBegin = msg.content.begin() + msg.offset;
			contentEnd = msg.content.end();
			// sendQueue.pop_front();
		}
		// first frame
		else if (msg.content.size() - msg.offset > maxSize &&
				 (flags & FrameType::Bulk))
		{
			flags = flags & ~FrameType::Bulk;
			flags = flags | FrameType::First;
			contentBegin = msg.content.begin() + msg.offset;
			contentEnd = msg.content.begin() + msg.offset + maxSize;
			// sendQueue.front().flags = flags & ~FrameType::Bulk;
			// sendQueue.front().offset += maxSize;
		}
		// intermediate frame
		else if (msg.content.size() - msg.offset > maxSize)
		{
			contentBegin = msg.content.begin() + msg.offset;
			contentEnd = msg.content.begin() + msg.offset + maxSize;
			// sendQueue.front().flags = flags & ~FrameType::Bulk;
			// sendQueue.front().offset += maxSize;
		}
		// last frame
		else
		{
			contentBegin = msg.content.begin() + msg.offset;
			contentEnd = msg.content.end();
			flags = flags | FrameType::Last;
			// sendQueue.pop_front();
		}
		msgBytes.push_back(flags);
		auto ret = SSL_write(ssl, contentBegin.base(), contentEnd - contentBegin);
		if (ret < 0)
		{
			throw std::runtime_error("SSL_write error");
		}
		auto encBuf = (uint8_t *)buffer;
		auto offset = 4;
		if ((flags & FrameType::Bulk) == FrameType::First)
		{
			offset += 4;
		}
		auto length = BIO_read(writeBio, encBuf + offset, nbytes - offset);
		if (length < 0)
		{
			throw std::runtime_error("BIO_read error");
		}
		encBuf[0] = msg.channel;
		encBuf[1] = flags;
		encBuf[2] = (length >> 8);
		encBuf[3] = (length & 0xff);
		if ((flags & FrameType::Bulk) == FrameType::First)
		{
			encBuf[4] = ((totalLength >> 24) & 0xff);
			encBuf[5] = ((totalLength >> 16) & 0xff);
			encBuf[6] = ((totalLength >> 8) & 0xff);
			encBuf[7] = ((totalLength >> 0) & 0xff);
		}
		return length + offset;
	}
	else
	{
		// sendQueue.pop_front();
		msgBytes.push_back(msg.channel);
		msgBytes.push_back(msg.flags);
		int length = msg.content.size();
		pushBackInt16(msgBytes, length);
		std::copy(msg.content.begin(), msg.content.end(),
				  std::back_inserter(msgBytes));
		std::copy(msgBytes.begin(), msgBytes.end(), (uint8_t *)buffer);
		return msgBytes.size();
	}
}

int main()
{

	struct sockaddr_in sa_serv;
	struct sockaddr_in sa_cli;
	int err = 0, client_len;
	int listen_sd = socket(AF_INET, SOCK_STREAM, 0);
	int opt = 1;
	setsockopt(listen_sd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
	memset(&sa_serv, 0, sizeof(sa_serv));
	sa_serv.sin_family = AF_INET;
	sa_serv.sin_addr.s_addr = INADDR_ANY;
	sa_serv.sin_port = htons(5277); /* Server Port number */
	err = bind(listen_sd, (struct sockaddr *)&sa_serv,
			   sizeof(sa_serv));

	// /* Receive a TCP connection. */

	err = listen(listen_sd, 5);
	CHK_ERR(err, "listen");

	client_len = sizeof(sa_cli);
	sd = accept(listen_sd, (struct sockaddr *)&sa_cli, (socklen_t *)&client_len);
	printf("Connection from %lx, port %x\n",
		   sa_cli.sin_addr.s_addr, sa_cli.sin_port);
	CHK_ERR(sd, "accept");
	close(listen_sd);

	handleVersionReq(sd);
	initializeSslContext();
	initializeSsl();

	char buf[0x1000] = {0};
	int ll = recv(sd, buf, 0x1000, 0);
	printf("recved ssl handshake packet size: %d\n", ll);
	BIO_write(readBio, buf + 6, ll - 6);
	// ll = recv(sd, buf, 300, 0);
	// printf("recved ssl handshake packet size: %d\n", ll);
	// BIO_write(readBio, buf + 4, ll - 4);

	handleSslHandshake(buf, ll);

	ll = recv(sd, buf, 0x1000, 0);
	printf("recved ssl handshake packet size: %d\n", ll);
	BIO_write(readBio, buf + 6, ll - 6);

	handleSslHandshake(buf, ll);

	while (1)
	{
		ll = recv(sd, buf, 0x500, 0);
		printf("recv len: %d\n", ll);
		for (int x = 0; x < ll; x++)
		{
			printf("%2x ", buf[x] & 0xff);
		}
		printf("\n");
		sleep(1);
		// send(sd, packet0, sizeof(packet0) - 1, 0);
	}

	return 0;
}
