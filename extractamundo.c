#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <stdint.h>
#include <unistd.h>
#include <string.h>
#include <strings.h>
#include <linux/limits.h>
#include <sys/mman.h>
#include <arpa/inet.h>
#include "pngcrctable.h"

#define DEBUG 0

int openoutfile(char* prefix, int* count, char* extension)
{
	char outname[PATH_MAX];
	int outfd;

	sprintf(outname, "%s-%04d.%s", prefix, *count, extension);

	*count += 1;

	printf("%s: ", outname);

	outfd = open(outname, O_CREAT | O_WRONLY, 0644);

	if ( outfd < 0 )
	{
		perror("open for writing");
		return -1;
	}

	return outfd;
}


typedef struct riffheader_t
{
	char		riff_fourcc[4];
	uint32_t	filesize;
	char		webp_fourcc[4];
} riffheader;

int extractwebp(uint8_t* data, size_t rembytes, char* prefix, int* count)
{
	riffheader* head;
	int outfd;
	char outname[1024];

	head = (riffheader*)data;

	if ( rembytes < 12 )
		return 1;

	if ( memcmp(head->webp_fourcc, "WEBP", 4) != 0 )
		return 1;

	if ( head->filesize + 8 > rembytes )
		return 1;

	outfd = openoutfile(prefix, count, "webp");

	if ( outfd < 0 )
		return 1;

	write(outfd, data, head->filesize + 8);

	close(outfd);

	printf("%s: %d bytes\n", outname, head->filesize + 8);

	return head->filesize + 8;
}

typedef struct pngchunk_t
{
	uint32_t length;
	char	 type[4];	/* Technically not a string */
} pngchunk;

typedef struct pngihdr_t
{
	uint32_t width;
	uint32_t height;
	uint8_t	 depth;
	uint8_t	 color_type;
	uint8_t	 filter_method;
	uint8_t	 interlace_method;
} pngihdr;

/* This code is from the libPNG documentation. 
 * http://www.libpng.org/pub/png/spec/1.2/PNG-CRCAppendix.html
 */
unsigned long update_crc(unsigned long crc, unsigned char *buf,
		    int len)
{
	unsigned long c = crc;
	int n;

	for (n = 0; n < len; n++)
		c = crc_table[(c ^ buf[n]) & 0xff] ^ (c >> 8);

	return c;
}

/* Return the CRC of the bytes buf[0..len-1]. */
unsigned long pngcrc(unsigned char *buf, int len)
{
	return update_crc(0xffffffffL, buf, len) ^ 0xffffffffL;
}

int readchunk(int outfd, uint8_t* data, size_t rembytes, int* offset)
{
	pngchunk* chunkheader;
	size_t	chunklen;
	uint32_t  compcrc;
	uint32_t  storedcrc;

	chunkheader = (pngchunk*)(data + *offset);

	/* The length field doesn't include the 4 byte length field, 4 byte
	 * Chunk Type field, or the 4 byte CRC field.
	 */
	chunklen = ntohl(chunkheader->length) + 4 + 4 + 4;
	
	if ( DEBUG )
		printf("%c%c%c%c %lu bytes\n", 
			     chunkheader->type[0], chunkheader->type[1],
			     chunkheader->type[2], chunkheader->type[3],
			     chunklen);

	compcrc = pngcrc((unsigned char*)chunkheader->type, 
			 ntohl(chunkheader->length) + 4);
	memcpy(&storedcrc, data + *offset + chunklen - 4, 4);

	if ( storedcrc != ntohl(compcrc) )
	{
		fprintf(stderr, "Warning: PNG CRC mismatch, file corruption likely\n");
	}

	if ( strncasecmp(chunkheader->type, "IHDR", 4) == 0 )
	{
		pngihdr* ihdr;

		ihdr = (pngihdr*)(data + *offset + sizeof(pngchunk));

		printf("PNG Image: %dx%d, %d bit color type 0x%x", 
				ntohl(ihdr->width), ntohl(ihdr->height), 
				ihdr->depth, ihdr->color_type);
	}

	if ( strncasecmp(chunkheader->type, "TEXT", 4) == 0 )
	{
		int textlen = ntohl(chunkheader->length);
		unsigned char* textdata;
		textdata = malloc(sizeof(unsigned char) * textlen + 1);
		if ( textdata != NULL )
		{
			for ( int lcv = 0; lcv < textlen; lcv++ )
			{
				textdata[lcv] = data[*offset + sizeof(pngchunk) + lcv];
				if( textdata[lcv] == '\0' )
					textdata[lcv] = ' ';
			}
			textdata[textlen] = '\0';
			printf("%s\n", textdata);
			free(textdata);
		}
	}

	if ( chunklen > (rembytes - *offset) )
	{
		fprintf(stderr, "Error: PNG chunk would extend past the end of the file\n");
		return -1;
	}

	if( write(outfd, data + *offset, chunklen) < chunklen )
	{
		fprintf(stderr, "Warning: short write of PNG chunk, output file corrupt\n");
		return -1;
	}

	*offset += chunklen;

	if ( strncasecmp(chunkheader->type, "IEND", 4) == 0 )
	{
		return 1;
	}

	return 0;
}

int extractpng(uint8_t* data, size_t rembytes, char* prefix, int* count)
{
	int offset = 8;
	char outname[PATH_MAX];
	int outfd;

	outfd = openoutfile(prefix, count, "png");
	if ( outfd < 0 )
		return 1;

	write(outfd, data, 8);	/* PNG header */
	
	while ( readchunk(outfd, data, rembytes, &offset) == 0 )
	{ }

	close(outfd);

	printf(" %d bytes\n", offset);

	return offset;
}

typedef struct jfifsegment_t
{
	unsigned char magic;
	unsigned char app0;
	unsigned short length;
} jfifsegment;

int readsegment(int outfd, uint8_t* data, size_t rembytes, int* offset)
{
	jfifsegment* seg;

	seg = (jfifsegment*)data + offset;


	
}

int extractjfif(uint8_t* data, size_t rembytes, char* prefix, int* count)
{
	int offset = 2;
	int outfd;

	outfd = openoutfile(prefix, count, "jpg");
	if ( outfd < 0 )
		return 1;

	while ( readsegment(outfd, data, rembytes, &offset) == 0 )
	{ }

	close(outfd);

	return offset;
}


int finddata(int fd, char* prefix, int* count)
{
	struct stat fileinfo;
	uint8_t* data;
	int	 lcv;

	if ( fstat(fd, &fileinfo) < 0 )
	{
		perror("fstat");
		return -1;
	}

	data = mmap(NULL, fileinfo.st_size, PROT_READ, MAP_PRIVATE, fd, 0);

	if ( data == MAP_FAILED )
	{
		perror("mmap");
		return -1;
	}

	for ( lcv = 0; lcv < (fileinfo.st_size - 8); lcv++ )
	{
		if ( data[lcv]   == 'R' &&
		     data[lcv+1] == 'I' &&
		     data[lcv+2] == 'F' &&
		     data[lcv+3] == 'F' )
		{
			lcv += extractwebp(&data[lcv], fileinfo.st_size - lcv, prefix, count);
		}

		if ( data[lcv]   == 0x89 &&
		     data[lcv+1] == 'P'  &&
		     data[lcv+2] == 'N'  &&
		     data[lcv+3] == 'G'  &&
		     data[lcv+4] == '\r' &&
		     data[lcv+5] == '\n' &&
		     data[lcv+6] == 0x1a &&
		     data[lcv+7] == '\n' )
		{
			lcv += extractpng(&data[lcv], fileinfo.st_size - lcv, prefix, count);
		}

		if ( data[lcv]   == 0xff &&
		     data[lcv+1] == 0xd8 &&
		     data[lcv+2] == 0xff &&
		     (data[lcv+3] & 0xf0) == 0xe0 )
		{
			lcv += extractjfif(&data[lcv], fileinfo.st_size - lcv, prefix, count);
		}
	}

	munmap(data, fileinfo.st_size);

	return 0;
}

int main(int argc, char** argv)
{
	int fd;
	int lcv;
	int count;

	count = 1;

	if ( argc < 3 || strcmp(argv[1], "-h") == 0 )
	{
		printf("Usage: %s <prefix> <file to extract>...\n", argv[0]);
		return 0;
	}	

	for ( lcv = 2; lcv < argc; lcv++ )
	{
		fd = open(argv[lcv], O_RDONLY);

		if ( fd < 0 )
		{
			perror(argv[lcv]);
			continue;
		}

		finddata(fd, argv[1], &count);

		close(fd);
	}
	return 0;
}
