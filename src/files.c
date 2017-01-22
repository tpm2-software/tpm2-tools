#include <errno.h>
#include <stdio.h>

#include "files.h"
#include "log.h"
static TPMS_CONTEXT context;

int loadDataFromFile(const char *fileName, UINT8 *buf, UINT16 *size)
{
    UINT16 count = 1, left;
    FILE *f;
    if ( size == NULL || buf == NULL || fileName == NULL )
        return -1;

    f = fopen(fileName, "rb+");
    if( f == NULL )
    {
        printf("File(%s) open error.\n", fileName);
        return -2;
    }

    left = *size;
    *size = 0;
    while( left > 0 && count > 0 )
    {
        count = fread(buf, 1, left, f);
        *size += count;
        left -= count;
        buf += count;
    }

    if( *size == 0 )
    {
        printf("File read error\n");
        fclose(f);
        return -3;
    }
    fclose(f);
    return 0;
}

int saveDataToFile(const char *fileName, UINT8 *buf, UINT16 size)
{
    FILE *f;
    UINT16 count = 1;
    if( fileName == NULL || buf == NULL || size == 0 )
        return -1;

    f = fopen(fileName, "wb+");
    if( f == NULL )
    {
        printf("File(%s) open error.\n", fileName);
        return -2;
    }

    while( size > 0 && count > 0 )
    {
        count = fwrite(buf, 1, size, f);
        size -= count;
        buf += count;
    }

    if( size > 0 )
    {
        printf("File write error\n");
        fclose(f);
        return -3;
    }

    fclose(f);
    return 0;
}

int saveTpmContextToFile(TSS2_SYS_CONTEXT *sysContext, TPM_HANDLE handle, const char *fileName)
{
    TPM_RC rval;

    rval = Tss2_Sys_ContextSave( sysContext, handle, &context);
    if( rval == TPM_RC_SUCCESS &&
        saveDataToFile(fileName, (UINT8 *)&context, sizeof(TPMS_CONTEXT)) )
        rval = TPM_RC_FAILURE;

    if( rval != TPM_RC_SUCCESS )
    {
        printf("\n......ContextSave:Save handle 0x%x context failed. TPM Error:0x%x......\n", handle, rval);
        return -1;
    }

    return 0;
}

int loadTpmContextFromFile(TSS2_SYS_CONTEXT *sysContext, TPM_HANDLE *handle, const char *fileName)
{
    TPM_RC rval = TPM_RC_SUCCESS;
    UINT16 size = sizeof(TPMS_CONTEXT);

    if( loadDataFromFile(fileName, (UINT8 *)&context, &size) )
        rval = TPM_RC_FAILURE;
    if( rval == TPM_RC_SUCCESS )
        rval = Tss2_Sys_ContextLoad(sysContext, &context, handle);

    if( rval != TPM_RC_SUCCESS )
    {
        printf("\n......ContextLoad Error. TPM Error:0x%x......\n", rval);
        return -1;
    }

    return 0;
}

int checkOutFile(const char *path)
{
    FILE *fp = fopen(path,"rb");
    if(NULL != fp)
    {
        fclose(fp);
        printf("OutFile: %s Already Exist, Please Rename OR Delete It!\n",path);
        return -1;
    }
    return 0;
}

int getFileSize(const char *path, long *fileSize)
{
    int rc = -1;
    FILE *fp = fopen(path,"rb");
    if(NULL == fp)
    {
        LOG_ERR("fopen on file: \"%s\"  failed: %s !\n", path, strerror(errno));
        return -1;
    }
    fseek(fp, 0, SEEK_SET);
    fseek(fp, 0, SEEK_END);
    long size = ftell(fp);
    if (size < 0) {
        LOG_ERR("ftell on file \"%s\" failed: %s", path, strerror(errno));
        goto err;
    }

    *fileSize = size;
    rc = 0;

err:
    fclose(fp);
    return rc;
}
