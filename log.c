#include "logger.h"
#include <stdio.h>
#include <stdlib.h>
#include <time.h>

void logger(const char* tag, const char* message) {
   time_t now;
   time(&now);
//   printf("%s [%s]: %s\n", ctime(&now), tag, message);
   bool LogCreated;      //keeps track whether the log file is created or not

   FILE * file;

   if (!LogCreated) {
     file = fopen(LOGFILE, "w");
     LogCreated = true;
   } else
     file = fopen(LOGFILE, "a");

   if (file == NULL) {
     if (LogCreated)
       LogCreated = false;
     return;
   } else {
     fprintf(file, "%s [%s]: %s\n", ctime(&now), tag, message);
     fprintf(file, "/n");
     //fputs(message, file);
     fclose(file);
   }

   if (file)
     fclose(file);
}
