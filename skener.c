/* 
  Antivirus scanner
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>
#include <dirent.h>
#include <elf.h>
#include <fcntl.h>
#include <pwd.h>

//infection indicator
#define MAGIC 6585
#define MAX_BUF 1024

static int magic = MAGIC;
//virus detection
//return 2 if virus found
int detect(char *filename, int hd)
{
    //handle for temp file
   int fd;
   //file info
   struct stat stat;
   char *data;
   char tmpfile[MAX_BUF];
   char cmd[MAX_BUF]="\0";
   int tmagic;	  // Store files magic number
   int magicloc;  // Location of magic number
   Elf32_Ehdr ehdr;


/* check for magic(virus identificator) at the end of the file */
   if(fstat(hd, &amp;stat) &lt; 0) return 1;
   magicloc = stat.st_size - sizeof(magic);
   if( lseek(hd, magicloc, SEEK_SET) != magicloc ) return 1;

   //load magic character
   if(read(hd, &amp;tmagic, sizeof(magic)) != sizeof(magic)) return 1;
   //if file is infected, do not infect again
   if(tmagic == MAGIC) return 2;
   if(lseek(hd, 0, SEEK_SET) != 0) exit(1);


   return 0;
}

//search current directory for executable ELF files
void scan_dir(char *directory)
{
    int hd, r;
    DIR *dd;
    struct dirent *dirp;
    char vfile[256];
    
    /* open directory */
    dd = opendir(directory);
    
    // search entire directory
    if(dd != NULL) {
        while ((dirp = readdir(dd))) {
            r = 0;
            sprintf(vfile, "%s/%s", directory, dirp->d_name);
            // check if file is an ELF executable
            if (strstr(vfile, ".") != NULL) {
                if (strcmp(strstr(vfile, "."), ".so") == 0 || strcmp(strstr(vfile, "."), ".o") == 0 || strcmp(strstr(vfile, "."), ".a") == 0) {
                    continue;
                }
            }
            hd = open(vfile, O_RDONLY);
            if (hd >= 0) {
                int status = detect(vfile, hd);
                if (status == 2) {
                    printf("%s - INFECTED\n", vfile);
                } else if (status == 0) {
                    printf("%s - CLEAN\n", vfile);
                }
                close(hd);
            }
        }
        closedir(dd);
    }
}



int main(int argc, char *argv[], char *envp[])
{
  
   if (argc &lt; 2) {
   	printf("Pouzitie %s adresar\n",argv[0]);
	exit(1);
   }
   printf("Prehladavam adresar %s\n",argv[1]); 
   //scan directory
   scan_dir(argv[1]);
   return 0;
}