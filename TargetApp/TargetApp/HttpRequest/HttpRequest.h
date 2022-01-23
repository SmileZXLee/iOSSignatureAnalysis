//
//  HttpRequest.h
//  TargetApp
//
//  Created by 李兆祥 on 2022/1/20.
//

#import <Foundation/Foundation.h>

NS_ASSUME_NONNULL_BEGIN

@interface HttpRequest : NSObject
typedef void(^kGetDataEventHandler) (BOOL result, id data);
///post请求 postData是一个字典
+(void)postInterface:(NSString *)interface postData:(id)postData callBack:(kGetDataEventHandler)_result;
///get请求
+(void)getInterface:(NSString *)interface callBack:(kGetDataEventHandler)_result;
@end

NS_ASSUME_NONNULL_END
