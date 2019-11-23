#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <stdint.h>
#include <unistd.h>
#include <string.h>
#include <strings.h>
#include <ctype.h>
#include <linux/limits.h>
#include <sys/mman.h>
#include <arpa/inet.h>
#include "pngcrctable.h"
#include "mp3tables.h"

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
	char		content_fourcc[4];
} riffheader;

int extractriff(uint8_t* data, ssize_t rembytes, char* prefix, int* count)
{
	riffheader* head;
	int outfd;
	char outname[1024];
	char ext[5];

	head = (riffheader*)data;

	if ( rembytes < 12 )
		return 1;

	if ( head->filesize + 8 > rembytes )
		return 1;

	for ( int dignum = 0; dignum < 4; dignum++ )
	{
		char extdig = head->content_fourcc[dignum];

		if ( ! isprint(extdig) && extdig != '\0' )
			return 1;

		/* Technically it's a violation of the RIFF 
		 * spec to use whitespace in this part, but 
		 * does that stop developers?  No.
		 */
		if ( isspace(extdig) )
			extdig = '\0';

		ext[dignum] = extdig;
	}
	ext[4] = '\0';

	outfd = openoutfile(prefix, count, ext);

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

int readchunk(int outfd, uint8_t* data, ssize_t rembytes, int* offset)
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

/* I would like to take a moment to show my appreciation for the PNG file
 * format, which is exceptionally well designed and documented.
 */
int extractpng(uint8_t* data, ssize_t rembytes, char* prefix, int* count)
{
	int offset = 8;
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

typedef struct jpegsofheader_t
{
	uint8_t	precision;
	uint16_t height;
	uint16_t width;
	uint8_t components;
	uint8_t id;
	uint8_t sampleres;
	uint8_t quanttable;
} jpegsofheader;

int readsegment(int outfd, uint8_t* data, ssize_t rembytes, int* offset)
{
	jfifsegment* seg;

	if ( (rembytes - *offset) < 4 )
	{
		fprintf(stderr, "EOF reached before we found any image data.\n");
		*offset = 1;	/* Probably not a real JPEG file */
		return -1;
	}

	seg = (jfifsegment*)(data + *offset);

	if ( seg->magic != 0xff )
	{
		printf("Segment header incorrect\n");
		return -1;
	}

	if ( seg->app0 == 0xd8 )
	{
		write(outfd, data + *offset, 2);
		*offset += 2;
		return 0;
	}

	if ( seg->app0 == 0xd9 )
	{
		write(outfd, data + *offset, 2);
		*offset += 2;
		printf(" (%d bytes)\n", *offset);
		return 1;
	}

	if ( (seg->app0 & 0xf0 ) == 0xc0 && (seg->app0 != 0xc4) )
	{
		jpegsofheader* sof;

		sof = (jpegsofheader*)(data + *offset + 3);
		printf("%d x %d", ntohs(sof->width), ntohs(sof->height));
	}

	// Unfortunately JPEG doesn't provide a way to determine the
	// end of a Scan without doing the decode.  So we have to 
	// just look for the EOF marker.  
	if ( seg->app0 == 0xda )
	{
		int startoff = *offset;
		for ( ; (rembytes - *offset - 1) > 0; *offset += 1 )
		{
			if ( data[*offset] == 0xff &&
			     data[*offset+1] == 0xd9 )
			{
				write(outfd, data + startoff, *offset - startoff);
				return 0;
			}
		}
		*offset = startoff + 1;
		fprintf(stderr, "Error: EoF reached without finding EoI marker\n");
		return -1;
	}


	uint16_t len = ntohs(seg->length);
	write(outfd, data + *offset, len + 2);
	*offset += len + 2;

	return 0;	
}

int extractjfif(uint8_t* data, ssize_t rembytes, char* prefix, int* count)
{
	int offset = 0;
	int outfd;

	outfd = openoutfile(prefix, count, "jpg");
	if ( outfd < 0 )
		return 1;

	while ( readsegment(outfd, data, rembytes, &offset) == 0 )
	{ }

	close(outfd);

	return offset;
}

uint32_t syncsafe_decode(uint8_t syncsafe[4])
{
	return (syncsafe[0] << 21) + 
	       (syncsafe[1] << 14) +
	       (syncsafe[2] << 7)  +
	       (syncsafe[3]);
}

typedef struct id3v2_t
{
	char		id[3];
	uint8_t		v_maj;
	uint8_t		v_min;
	uint8_t		flags;
	uint8_t		ss_size[4];
} id3v2;	

typedef struct mp3_t
{
	unsigned int		emphasis:2;
	unsigned int		original:1;
	unsigned int		copyright:1;
	unsigned int		modeext:2;
	unsigned int		channels:2;
	unsigned int		private:1;
	unsigned int		padded:1;
	unsigned int		samplerate:2;
	unsigned int		bitrate:4;
	unsigned int		protected:1;
	unsigned int		layer:2;
	unsigned int		vers:2;
	unsigned int		sync:11;
} mp3;

int extractmp3frame(int outfd, uint8_t* data, ssize_t rembytes, int* offset)
{
	mp3*		mp3head;

	/* C bitfields are treacherous, since the header is in MSB form 
	 * we need to convert it to LSB, but doing the conversion on the 
	 * bitfields is too late.  We need to do it on the original data,
	 * hence this mess.
	 */
	if ( (*offset + 4) > rembytes )
		return -1;

	uint32_t msbdata;
	uint32_t lsbdata;
	memcpy(&msbdata, data + *offset, 4);
	lsbdata = ntohl(msbdata);
	mp3head = (mp3*) &lsbdata;

	if ( mp3head->sync != 0x7FF  || 
	     mp3head->bitrate == 0   ||
	     mp3head->bitrate == 0xf || 
	     mp3head->samplerate == 0x3 )
	{
		fprintf(stderr, "MP3 header not found %x != %x, %d %d\n", mp3head->sync, 0x7FF, mp3head->bitrate, mp3head->samplerate);
		return 1;
	}

	int bittable;
	if ( mp3head->vers == 0x3 )
		bittable = mp3head->layer - 1;
	else if ( mp3head->vers == 0x2 )
		bittable = mp3head->layer + 2;
	else
	{
		fprintf(stderr, "MPEG version/layer combo not supported v.%d l.%d\n", mp3head->vers, mp3head->layer);
		return 1;
	}

	uint32_t framelength;
	framelength = (1440 * mp3bitrates[bittable][mp3head->bitrate]) / 
			 mp3samplerates[mp3head->samplerate] + mp3head->padded;

	write(outfd, data + *offset, framelength);

	*offset += framelength;

	printf("MP3 v.%d layer %d crc: %d bitrate: %d samplerate: %d, frame len: %d\n",
			4 - mp3head->vers, 4 - mp3head->layer, 
			1 - mp3head->protected,
			mp3bitrates[bittable][mp3head->bitrate], 
			mp3samplerates[mp3head->samplerate], 
			framelength);

	return 0;
}

int extractmp3(uint8_t* data, ssize_t rembytes, char* prefix, int* count)
{
	id3v2*		id3head;
	int		offset = 0;
	uint32_t	size;
	int		outfd = 0;

	if ( data[0] == 'i' )
	{

		id3head = (id3v2*)data;

		/* Apply some heuristics to avoid false positives.  There's no
		 * checksum field or anything so we just have to look for 
		 * weird/invalid data.  This isn't perfect and we will have some
		 * false positives if the data is highly random and sparse.
		 */
		if ( id3head->v_maj > 5 || 
			id3head->v_min > 4 ||
			(id3head->flags & 0x0F ) != 0 ||
			(id3head->ss_size[0] & 0x80) != 0 ||
			(id3head->ss_size[1] & 0x80) != 0 ||
			(id3head->ss_size[2] & 0x80) != 0 ||
			(id3head->ss_size[3] & 0x80) != 0 ||
			rembytes < 10)
		{
			return 1;
		}

		outfd = openoutfile(prefix, count, "mp3");
		if ( outfd < 0 )
			return 1;

		size = syncsafe_decode(id3head->ss_size);

		offset += size + 10;

		printf("ID3v2.%d.%d (%d bytes)\n", id3head->v_maj, id3head->v_min, size);

		write(outfd, data, size + 10);
	}

	if ( outfd == 0 )
	{
		outfd = openoutfile(prefix, count, "mp3");
		if ( outfd < 0 )
			return 1;
	}

	/* In a set of random bits the MP3 header is much too common.
	 * A single header isn't really sufficient to assume that we
	 * are looking at a valid MP3 file, especially without the
	 * checksum.  So we require four valid MP3 headers in a row, 
	 * two if the checksums are in use.
	 */

	while ( extractmp3frame(outfd, data, rembytes, &offset) == 0 )
	{ }

	close(outfd);

	return offset;
}

typedef struct __attribute__((__packed__)) ogg_t
{
	char		magic[4];
	uint8_t		version;
	uint8_t		type;
	uint64_t	granuleposition;
	uint32_t	serialnum;
	uint32_t	pageseq;
	uint32_t	crc;
	uint8_t		numsegs;
} ogg;

int extractogg(uint8_t* data, ssize_t rembytes, char* prefix, int* count)
{
	int offset = 0;
	ogg* header;
	uint32_t lastpage;
	int outfd;

	if ( rembytes < sizeof(ogg) )
	{
		fprintf(stderr, "Remaining space too small for an OGG file\n");
		return 1;
	}

	header = (ogg*)data;

	if ( memcmp(header->magic, "OggS", 4) != 0 )
	{
		fprintf(stderr, "Error: Not an OGG segment\n");
		return 1;
	}

	if ( header->version != 0 )
	{
		fprintf(stderr, "Error: Only OGG version 1 containers are suported.  This is %d\n", header->version + 1);
		return 1;
	}

	if ( header->type != 0x2 )
	{
		fprintf(stderr, "Warning: Did not see first packet of OGG bitstream\n");
	}
	lastpage = header->pageseq - 1;

	while ( header->type != 0x4 )
	{
		if ( memcmp(header->magic, "OggS", 4) != 0 )
		{
			fprintf(stderr, "Error: Premature break in OGG sequence %x%x%x%x\n", header->magic[0], header->magic[1], header->magic[2], header->magic[3]);
			return 1;
		}

		if ( header->pageseq != lastpage + 1 )
		{
			fprintf(stderr, "Warning: Break in page sequence, prev page: %u, curr page: %u\n", lastpage, header->pageseq);
		}

		lastpage = header->pageseq;

		offset += sizeof(ogg);
		uint8_t* segtable = data + offset;
		offset += header->numsegs;

		for ( int seg = 0; seg < header->numsegs; seg++ )
		{
			offset += segtable[seg];
		}

		if ( rembytes < sizeof(ogg) + offset )
		{
			fprintf(stderr, "OGG file truncated\n");
			return 1;
		}

		header = (ogg*)(data + offset);
	}

	outfd = openoutfile(prefix, count, "ogg");
	if ( outfd < 0 )
		return offset;

	write(outfd, data, offset);

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
			lcv += extractriff(&data[lcv], fileinfo.st_size - lcv, prefix, count);
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

		if ((data[lcv]   == 'I' &&
		     data[lcv+1] == 'D' &&
		     data[lcv+2] == '3') ||
		    (data[lcv]   == 0xFF &&
		    (data[lcv+1] & 0xE0) == 0xE0) )
		{
			lcv += extractmp3(&data[lcv], fileinfo.st_size - lcv, prefix, count);
		}

		if (data[lcv]   == 'O' &&
	 	    data[lcv+1] == 'g' &&
		    data[lcv+2] == 'g' &&
		    data[lcv+3] == 'S' )
		{
			lcv += extractogg(&data[lcv], fileinfo.st_size - lcv, prefix, count);
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
		printf("%s\n", argv[lcv]);
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
