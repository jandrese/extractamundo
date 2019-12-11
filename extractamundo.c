#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <stdint.h>
#include <unistd.h>
#include <string.h>
#include <strings.h>
#include <ctype.h>
#include <getopt.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <arpa/inet.h>
#include <linux/limits.h>
#include "pngcrctable.h"
#include "mp3tables.h"

typedef struct conf_t
{
	char*	prefix;
	char*	extractdir;
	char*	sourcefile;
	int	debuglevel;
	int	overwritemode;
	int	dumpunknown;
	int	zeropad;
	char	padcharacter;
	int	recursivemode;
	int	count;
	char	comment[1024];
} conf;

int writeoutput(char* data, int size, conf* config, char* extension)
{
	char outname[PATH_MAX];
	int outfd;

	sprintf(outname, "%s-%04d.%s", config->prefix, config->count, extension);

	config->count += 1;

	outfd = open(outname, O_CREAT | O_WRONLY, 0644);

	if ( outfd < 0 )
	{
		perror("open for writing");
		return -1;
	}

	printf("%s: (%d bytes)\n", outname, size);

	int written = 0;
	while ( written < size )
	{
		int lastwrite = write(outfd, data + written, size - written);

		if ( lastwrite <= 0 )
		{
			perror("write");
			close(outfd);
			return -1;
		}

		written += lastwrite;	
	}

	close(outfd);

	return 0;
}

typedef struct riffheader_t
{
	char		riff_fourcc[4];
	uint32_t	filesize;
	char		content_fourcc[4];
} riffheader;

int extractriff(uint8_t* data, ssize_t rembytes, conf* config)
{
	riffheader* head;
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

		extdig = tolower(extdig);

		ext[dignum] = extdig;
	}
	ext[4] = '\0';

	if ( writeoutput((char*)data, head->filesize + 8, config, ext) < 0 )
		return 1;

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

int readpngchunk(uint8_t* data, ssize_t rembytes, int* offset, conf* config)
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
	
	if ( config->debuglevel >= 2 )
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
int extractpng(uint8_t* data, ssize_t rembytes, conf* config)
{
	int offset = 8;
	int ret;

	while ( (ret = readpngchunk(data, rembytes, &offset, config)) == 0 )
	{ }

	if ( ret < 0 )
	{
		fprintf(stderr, "PNG Decode failed\n");
		return 1;
	}

	writeoutput((char*)data, offset, config, "png");

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

int readjfifsegment(uint8_t* data, ssize_t rembytes, int* offset, conf* config)
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
		if ( config->debuglevel >= 1 )
			printf("JFIF Segment header incorrect, file corrupt or not a JPEG\n");
		return -1;
	}

	if ( seg->app0 == 0xd8 )
	{
		*offset += 2;
		return 0;
	}

	if ( seg->app0 == 0xd9 )
	{
		*offset += 2;
		return 1;
	}

	if ( (seg->app0 & 0xf0 ) == 0xc0 && (seg->app0 != 0xc4) )
	{
		jpegsofheader* sof;

		sof = (jpegsofheader*)(data + *offset + 3);
		printf("JPEG Image %d x %d ", ntohs(sof->width), ntohs(sof->height));
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
				*offset += 2;
				return 1;
			}
		}
		*offset = startoff + 1;
		fprintf(stderr, "Error: EoF reached without finding EoI marker\n");
		return -1;
	}

	/* Any other kind of marker we assume is just an application marker 
	 * of some kind.
	 */
	*offset += ntohs(seg->length) + 2;
	return 0;
}

int extractjfif(uint8_t* data, ssize_t rembytes, conf* config)
{
	int offset = 0;
	int ret;

	while ((ret = readjfifsegment(data, rembytes, &offset, config)) == 0 )
	{
		if ( ret < 0 )
			return 1;
	}

	writeoutput((char*)data, offset, config, "jpg");

	return offset;
}

uint32_t syncsafe_decode(uint8_t syncsafe[4])
{
	return (syncsafe[0] << 21) + 
	       (syncsafe[1] << 14) +
	       (syncsafe[2] << 7)  +
	       (syncsafe[3]);
}

typedef struct __attribute__((__packed__)) id3v1_t
{
	char		header[3];
	char		title[30];
	char		artist[30];
	char		album[30];
	char		year[4];
	char		comment[28];
	char		tracknumflag;
	char		tracknum;
	char		genre;
} id3v1;

typedef struct __attribute__((__packed__)) id3v1_extended_t
{
	char		header[4];
	char		title[60];
	char		artist[60];
	char		album[60];
	char		speed;
	char		genre[30];
	char		starttime[6];
	char		endtime[6];
} id3v1_extended;


typedef struct __attribute__((__packed__)) id3v2_t
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

int extractmp3frame(uint8_t* data, ssize_t rembytes, int* offset, conf* config)
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
		if ( config->debuglevel >= 2 )
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
		if ( config->debuglevel >= 2 )
			fprintf(stderr, "MPEG version/layer combo not supported v.%d l.%d\n", mp3head->vers, mp3head->layer);
		return 1;
	}

	uint32_t framelength;
	framelength = (1440 * mp3bitrates[bittable][mp3head->bitrate]) / 
			 mp3samplerates[mp3head->samplerate] + mp3head->padded;

	*offset += framelength;

	if ( config->debuglevel >= 1 )
		printf("MP3 v.%d layer %d crc: %d bitrate: %d samplerate: %d, frame len: %d\n",
			4 - mp3head->vers, 4 - mp3head->layer, 
			1 - mp3head->protected,
			mp3bitrates[bittable][mp3head->bitrate], 
			mp3samplerates[mp3head->samplerate], 
			framelength);

	/* XXX: I should do the Checksum calculation here if it is present
	 * in the file, but I have not been able to find an example file 
	 * with the checksums enabled to test with, nor a good document
	 * describing how the checksum is calculated.  I suspect these two
	 * facts may be related.
	 */

	return 0;
}

int extractmp3(uint8_t* data, ssize_t rembytes, conf* config)
{
	int		offset = 0;
	uint32_t	size;

	if ( data[0] == 'i' )
	{
		id3v2*		id3head;
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

		size = syncsafe_decode(id3head->ss_size);

		offset += size + 10;

		/* Not followed by an MP3 header? */
		if ( data[offset] != 0xff || ((data[offset+1] & 0xE0) != 0xE0))
		{
			if ( config->debuglevel >= 1 )
				fprintf(stderr, "Error: ID3v2 tag not followed by MP3 frame\n");
			return 1;
		}
	}

	int numframes = 0;
	while ( extractmp3frame(data, rembytes, &offset, config) == 0 )
	{
		numframes++;	
	}
	
	/* Yes the extended tag magic number is almost identical to the
	 * regular tag magic number, and an  extended tag could just be 
	 * a regular tag if the song title starts with a + character.  
	 * ID3 is kind of dumb.
	 */
	if ( data[offset]   == 'T' &&
	     data[offset+1] == 'A' &&
	     data[offset+2] == 'G' &&
	     data[offset+3] == '+' )
	{
		id3v1_extended* tag;
		tag = (id3v1_extended*) (data + offset);

		offset += sizeof(id3v1_extended);
	}

	if ( data[offset]   == 'T' &&
	     data[offset+1] == 'A' &&
	     data[offset+2] == 'G' )
	{
		/* ID3v1 tag */
		id3v1*	tag;
		tag = (id3v1*)(data + offset);

		offset += sizeof(id3v1);
	}
	else if ( numframes < 5 ) 
	{
		/* With only a small number of frames and no ID3 tag 
		 * this is probably not an MP3 file.  MP3's file format
		 * is very loose and the optional checksum is apparently
		 * almost never used, so the false positive rate is very high.
		 * This huristic gets the false positive rate down to a
		 * manageable level, and there's probably not a lot of
		 * interest in MP3 files that are less than a second long.
		 */
		return 1;
	}

	writeoutput((char*)data, offset, config, "mp3");

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

int extractogg(uint8_t* data, ssize_t rembytes, conf* config)
{
	int offset = 0;
	ogg* header;
	uint32_t lastpage;

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

	writeoutput((char*)data, offset, config, "ogg");

	return offset;
}

int check_createdir(char* dir)
{
	struct stat info;
	int ret;

	ret = stat(dir, &info);

	if ( ret < 0 && errno == ENOENT )
	{
		ret = mkdir(dir, 0755);

		if ( ret < 0 )
		{
			fprintf(stderr, "mkdir: ");
			perror(dir);
			exit(-1);
		}
	}

	if ( ret < 0 )
	{
		fprintf(stderr, "stat: ");
		perror(dir);
		exit(-1);
	}

	if ( S_ISDIR(info.st_mode) )
	{
		fprintf(stderr, "Error, extract directory '%s' already exists and is not a directory.  Use the -e option to choose a different directory\n", dir);
		exit(-1);
	}

	return 0;
}

int finddata(int fd, conf* config)
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

	lcv = 0;
	while ( lcv < (fileinfo.st_size - 8) )
	{
		if ( data[lcv]   == 'R' &&
		     data[lcv+1] == 'I' &&
		     data[lcv+2] == 'F' &&
		     data[lcv+3] == 'F' )
		{
			lcv += extractriff(&data[lcv], fileinfo.st_size - lcv, config);
		}
		else if ( data[lcv]   == 0x89 &&
		     data[lcv+1] == 'P'  &&
		     data[lcv+2] == 'N'  &&
		     data[lcv+3] == 'G'  &&
		     data[lcv+4] == '\r' &&
		     data[lcv+5] == '\n' &&
		     data[lcv+6] == 0x1a &&
		     data[lcv+7] == '\n' )
		{
			lcv += extractpng(&data[lcv], fileinfo.st_size - lcv, config);
		}
		else if ( data[lcv]   == 0xff &&
		     data[lcv+1] == 0xd8 &&
		     data[lcv+2] == 0xff &&
		     (data[lcv+3] & 0xf0) == 0xe0 )
		{
			lcv += extractjfif(&data[lcv], fileinfo.st_size - lcv, config);
		}
		else if ((data[lcv]   == 'I' &&
		     data[lcv+1] == 'D' &&
		     data[lcv+2] == '3') ||
		    (data[lcv]   == 0xFF &&
		    (data[lcv+1] & 0xE0) == 0xE0) )
		{
			lcv += extractmp3(&data[lcv], fileinfo.st_size - lcv, config);
		}
		else if (data[lcv]   == 'O' &&
	 	    data[lcv+1] == 'g' &&
		    data[lcv+2] == 'g' &&
		    data[lcv+3] == 'S' )
		{
			lcv += extractogg(&data[lcv], fileinfo.st_size - lcv, config);
		}	
		else
		{
			lcv++;
		}
	}

	munmap(data, fileinfo.st_size);

	return 0;
}

int printhelp()
{
	printf("Extractamundo -- Pulls known file types out of aggregate files\n");
	printf("\n");
	printf("Files are written to a directory you specify, by default 'extracted'\n");

	return 0;
}

int main(int argc, char** argv)
{
	int fd;
	int lcv;
	int opt;
	conf config;

	memset(&config, 0, sizeof(conf));

	config.count = 1;
	config.extractdir = "extracted";

	while (( opt = getopt(argc, argv, "e:dp:ouzc:rh")) != -1 )
	{
		switch(opt)
		{
		case 'e':
			config.extractdir = optarg;
		break;

		case 'd':
			config.debuglevel++;
		break;

		case 'p':
			config.prefix = optarg;
		break;

		case 'o':
			config.overwritemode = 1;
		break;
		
		case 'u':
			config.dumpunknown = 1;
		break;

		case 'z':
			config.zeropad = 1;
		break;

		case 'c':
			config.padcharacter = *optarg;
		break;

		case 'r':
			config.recursivemode = 1;
		break;

		case 'h':
		default:
			printhelp();
			return(-1);
		break;
		}
	}

	check_createdir(config.extractdir);

	for ( lcv = optind; lcv < argc; lcv++ )
	{
		printf("Extracting from %s\n", argv[lcv]);
		config.sourcefile = argv[lcv];
		fd = open(argv[lcv], O_RDONLY);

		if ( fd < 0 )
		{
			perror(argv[lcv]);
			continue;
		}

		finddata(fd, &config);

		close(fd);
	}
	return 0;
}
