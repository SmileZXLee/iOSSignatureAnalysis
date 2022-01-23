#line 1 "/Users/mac/Documents/GitHub/iOSSignatureAnalysis/HookApp/HookAppDylib/Logos/HookAppDylib.xm"


#import <UIKit/UIKit.h>

#import "ZXCodeFloor.h"

static __attribute__((constructor)) void _logosLocalCtor_f292e0e3(int __unused argc, char __unused **argv, char __unused **envp){
[ZXCodeFloor initAction];
}



#include <substrate.h>
#if defined(__clang__)
#if __has_feature(objc_arc)
#define _LOGOS_SELF_TYPE_NORMAL __unsafe_unretained
#define _LOGOS_SELF_TYPE_INIT __attribute__((ns_consumed))
#define _LOGOS_SELF_CONST const
#define _LOGOS_RETURN_RETAINED __attribute__((ns_returns_retained))
#else
#define _LOGOS_SELF_TYPE_NORMAL
#define _LOGOS_SELF_TYPE_INIT
#define _LOGOS_SELF_CONST
#define _LOGOS_RETURN_RETAINED
#endif
#else
#define _LOGOS_SELF_TYPE_NORMAL
#define _LOGOS_SELF_TYPE_INIT
#define _LOGOS_SELF_CONST
#define _LOGOS_RETURN_RETAINED
#endif

@class EncryptionTool; 
static id (*_logos_meta_orig$_ungrouped$EncryptionTool$AES128Encrypt$key$)(_LOGOS_SELF_TYPE_NORMAL Class _LOGOS_SELF_CONST, SEL, id, id); static id _logos_meta_method$_ungrouped$EncryptionTool$AES128Encrypt$key$(_LOGOS_SELF_TYPE_NORMAL Class _LOGOS_SELF_CONST, SEL, id, id); static id (*_logos_meta_orig$_ungrouped$EncryptionTool$aesEncrypt$key$)(_LOGOS_SELF_TYPE_NORMAL Class _LOGOS_SELF_CONST, SEL, id, id); static id _logos_meta_method$_ungrouped$EncryptionTool$aesEncrypt$key$(_LOGOS_SELF_TYPE_NORMAL Class _LOGOS_SELF_CONST, SEL, id, id); 

#line 12 "/Users/mac/Documents/GitHub/iOSSignatureAnalysis/HookApp/HookAppDylib/Logos/HookAppDylib.xm"

static id _logos_meta_method$_ungrouped$EncryptionTool$AES128Encrypt$key$(_LOGOS_SELF_TYPE_NORMAL Class _LOGOS_SELF_CONST __unused self, SEL __unused _cmd, id arg1, id arg2){
    NSLog(@"aes加密之前的明文：%@；aes的key：%@",arg1,arg2);
    return _logos_meta_orig$_ungrouped$EncryptionTool$AES128Encrypt$key$(self, _cmd, arg1, arg2);
}

static id _logos_meta_method$_ungrouped$EncryptionTool$aesEncrypt$key$(_LOGOS_SELF_TYPE_NORMAL Class _LOGOS_SELF_CONST __unused self, SEL __unused _cmd, id arg1, id arg2){
    NSLog(@"aes加密之前的明文：%@；aes的key：%@",arg1,arg2);
    return _logos_meta_orig$_ungrouped$EncryptionTool$aesEncrypt$key$(self, _cmd, arg1, arg2);
}

static __attribute__((constructor)) void _logosLocalInit() {
{Class _logos_class$_ungrouped$EncryptionTool = objc_getClass("EncryptionTool"); Class _logos_metaclass$_ungrouped$EncryptionTool = object_getClass(_logos_class$_ungrouped$EncryptionTool); { MSHookMessageEx(_logos_metaclass$_ungrouped$EncryptionTool, @selector(AES128Encrypt:key:), (IMP)&_logos_meta_method$_ungrouped$EncryptionTool$AES128Encrypt$key$, (IMP*)&_logos_meta_orig$_ungrouped$EncryptionTool$AES128Encrypt$key$);}{ MSHookMessageEx(_logos_metaclass$_ungrouped$EncryptionTool, @selector(aesEncrypt:key:), (IMP)&_logos_meta_method$_ungrouped$EncryptionTool$aesEncrypt$key$, (IMP*)&_logos_meta_orig$_ungrouped$EncryptionTool$aesEncrypt$key$);}} }
#line 23 "/Users/mac/Documents/GitHub/iOSSignatureAnalysis/HookApp/HookAppDylib/Logos/HookAppDylib.xm"
