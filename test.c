#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <stdint.h>
#include <unistd.h>
 
#define SECTOR_SIZE 512
#define MBR_SIZE SECTOR_SIZE
#define MBR_DISK_SIGNATURE_OFFSET 440
#define MBR_DISK_SIGNATURE_SIZE 4
#define PARTITION_TABLE_OFFSET 446
#define PARTITION_ENTRY_SIZE 16 // sizeof(PartEntry)
#define PARTITION_TABLE_SIZE 64 // sizeof(PartTable)
#define MBR_SIGNATURE_OFFSET 510
#define MBR_SIGNATURE_SIZE 2
#define MBR_SIGNATURE 0xAA55
#define BR_SIZE SECTOR_SIZE
#define BR_SIGNATURE_OFFSET 510
#define BR_SIGNATURE_SIZE 2
#define BR_SIGNATURE 0xAA55
 
typedef struct {
    unsigned char boot_type; // 0x00 - Inactive; 0x80 - Active (Bootable)
    unsigned char start_head;
    unsigned char start_sec;
    unsigned char start_cyl_hi;
    unsigned char start_cyl;
    unsigned char part_type;
    unsigned char end_head;
    unsigned char end_sec;
    unsigned char end_cyl_hi;
    unsigned char end_cyl;
    unsigned char abs_start_sec[4];
    unsigned char sec_in_part[4];
} PartEntry;
 
typedef struct {
    unsigned char boot_code[MBR_DISK_SIGNATURE_OFFSET];
    unsigned char disk_signature[4];
    unsigned long pad;
    unsigned char pt[62];
    unsigned short signature;
} MBR;
 
void print_computed(unsigned long sector) {
    unsigned long heads, cyls, tracks, sectors;
 
    sectors = sector % 63 + 1 /* As indexed from 1 */;
    tracks = sector / 63;
    cyls = tracks / 255 + 1 /* As indexed from 1 */;
    heads = tracks % 255;
    printf("(%3d/%5d/%1d)", heads, cyls, sectors);
}
 
int main(int argc, char *argv[]) {
    MBR *mbr = calloc(1, sizeof(MBR));
    mbr->disk_signature[0] = 0x4a;
    mbr->disk_signature[1] = 0xad;
    mbr->disk_signature[2] = 0x36;
    mbr->disk_signature[3] = 0xd5;
    mbr->signature = 0xAA55;
    mbr->pt[0] = 0x20; 
    mbr->pt[1] = 0x01;
    mbr->pt[2] = 0x03;
    mbr->pt[3] = 0x83;
    mbr->pt[4] = 0x5f;
    mbr->pt[5] = 0x50;
    mbr->pt[6] = 0x08;
    mbr->pt[7] = 0x00;
    mbr->pt[8] = 0x00;
    mbr->pt[9] = 0x00;
    mbr->pt[10] = 0x50;
    mbr->pt[11] = 0x00;
    mbr->pt[12] = 0x00;
    mbr->pt[13] = 0x00;
    mbr->pt[14] = 0x00;
    mbr->pt[15] = 0x00;
    mbr->pt[16] = 0x60;
    mbr->pt[17] = 0x41; 
    mbr->pt[18] = 0x03;
    mbr->pt[19] = 0x05;
    mbr->pt[20] = 0x3f;
    mbr->pt[21] = 0x90;
    mbr->pt[22] = 0x58;
    mbr->pt[23] = 0x00;
    mbr->pt[24] = 0x00;
    mbr->pt[25] = 0x00;
    mbr->pt[26] = 0x38;
    mbr->pt[27] = 0x00;
    mbr->pt[28] = 0x00;
    mbr->pt[29] = 0x01;
    unsigned char* charPtr=(unsigned char*) mbr;
    for(int i=0;i<sizeof(MBR);i++)
      printf("%02x ",charPtr[i]);
    return 0;
}