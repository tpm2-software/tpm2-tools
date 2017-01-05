#ifndef FILES_H
#define FILES_H

#include <sapi/tpm20.h>

int loadDataFromFile(const char *fileName, UINT8 *buf, UINT16 *size);
int saveDataToFile(const char *fileName, UINT8 *buf, UINT16 size);
int saveTpmContextToFile(TSS2_SYS_CONTEXT *sysContext, TPM_HANDLE handle, const char *fileName);
int loadTpmContextFromFile(TSS2_SYS_CONTEXT *sysContext, TPM_HANDLE *handle, const char *fileName);
int checkOutFile(const char *path);
int getFileSize(const char *path, long *fileSize);

#endif /* FILES_H */
