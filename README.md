# extractamundo

Extracts media files from a binary blob.  Currently supports RIFF encoded files like webp, JPEG, and PNG.

Usage:
extractamundo <prefix> <binary_file>... 

Files extracted will be numbered sequentially using the prefix you specify.  For example:

extractamundo foo data.bin
foo-0001.png
foo-0002.jpg
foo-0003.png
foo-0004.webp


