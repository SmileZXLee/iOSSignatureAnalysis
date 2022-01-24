//
//  EncryptionTool.m
//  TargetApp
//
//  Created by 李兆祥 on 2019/3/8.
//  Copyright © 2019 李兆祥. All rights reserved.
//

#import "EncryptionTool.h"
#import "CocoaSecurity.h"
#import <CommonCrypto/CommonDigest.h>
#import <CommonCrypto/CommonCryptor.h>
@implementation EncryptionTool
+(NSString *)aesEncrypt:(NSString *)data key:(NSString *)key{
    return [self AES128Encrypt:data key:key];
}

+(NSString *)aesDecryptWithBase64:(NSString *)data key:(NSString *)key{
    return [self AES128Decrypt:data key:key];
}
+ (NSString *)md5Hex:(NSString *)input{
    const char* str = [input UTF8String];
    unsigned char result[CC_MD5_DIGEST_LENGTH];
    CC_MD5(str, (CC_LONG)strlen(str), result);
    NSMutableString *ret = [NSMutableString stringWithCapacity:CC_MD5_DIGEST_LENGTH];
    
    for(int i = 0; i<CC_MD5_DIGEST_LENGTH; i++) {
        [ret appendFormat:@"%02x",result[i]];
    }
    return ret;
}

+(NSString *)AES128Encrypt:(NSString *)plainText key:(NSString *)key{
    char keyPtr[kCCKeySizeAES128+1];
    memset(keyPtr, 0, sizeof(keyPtr));
    [key getCString:keyPtr maxLength:sizeof(keyPtr) encoding:NSUTF8StringEncoding];
      
    NSData* data = [plainText dataUsingEncoding:NSUTF8StringEncoding];
    NSUInteger dataLength = [data length];
      
    size_t bufferSize = dataLength + kCCBlockSizeAES128;
    void *buffer = malloc(bufferSize);
    size_t numBytesEncrypted = 0;
    CCCryptorStatus cryptStatus = CCCrypt(kCCEncrypt,
                                          kCCAlgorithmAES128,
                                          kCCOptionPKCS7Padding|kCCOptionECBMode,
                                          keyPtr,
                                          kCCBlockSizeAES128,
                                          NULL,
                                          [data bytes],
                                          dataLength,
                                          buffer,
                                          bufferSize,
                                          &numBytesEncrypted);
    if (cryptStatus == kCCSuccess) {
        NSData *resultData = [NSData dataWithBytesNoCopy:buffer length:numBytesEncrypted];
        return [resultData base64EncodedStringWithOptions:NSDataBase64Encoding64CharacterLineLength];
    }
    free(buffer);
    return nil;
}

+(NSString *)AES128Decrypt:(NSString *)encryptText key:(NSString *)key{
    char keyPtr[kCCKeySizeAES128 + 1];
    memset(keyPtr, 0, sizeof(keyPtr));
    [key getCString:keyPtr maxLength:sizeof(keyPtr) encoding:NSUTF8StringEncoding];
      
    //NSData *data = [GTMBase64 decodeData:[encryptText dataUsingEncoding:NSUTF8StringEncoding]];
      
    NSData *data = [encryptText dataUsingEncoding:NSUTF8StringEncoding];
      
    NSUInteger dataLength = [data length];
    size_t bufferSize = dataLength + kCCBlockSizeAES128;
    void *buffer = malloc(bufferSize);
      
    size_t numBytesCrypted = 0;
    CCCryptorStatus cryptStatus = CCCrypt(kCCDecrypt,
                                          kCCAlgorithmAES128,
                                          kCCOptionPKCS7Padding|kCCOptionECBMode,
                                          keyPtr,
                                          kCCBlockSizeAES128,
                                          NULL,
                                          [data bytes],
                                          dataLength,
                                          buffer,
                                          bufferSize,
                                          &numBytesCrypted);
    if (cryptStatus == kCCSuccess) {
        NSData *resultData = [NSData dataWithBytesNoCopy:buffer length:numBytesCrypted];
        return [[NSString alloc] initWithData:resultData encoding:NSUTF8StringEncoding];
    }
    free(buffer);
    return nil;
}


@end
