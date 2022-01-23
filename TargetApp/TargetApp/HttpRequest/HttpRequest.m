//
//  HttpRequest.m
//  TargetApp
//
//  Created by 李兆祥 on 2022/1/20.
//

#import "HttpRequest.h"
#import "EncryptionTool.h"
#import "MBProgressHUD.h"
#define TimeOutSec 10
//#define kMainUrl @"http://localhost:8080/api/v1"
#define kMainUrl @"http://api.zxlee.cn:6303/api/v1"
@implementation HttpRequest
#pragma mark POST请求
+(void)postInterface:(NSString *)interface postData:(id)postData callBack:(kGetDataEventHandler)_result{
    [self baseInterface:interface postData:postData callBack:_result];
}
#pragma mark GET请求
+(void)getInterface:(NSString *)interface callBack:(kGetDataEventHandler)_result{
    [self baseInterface:interface postData:nil callBack:_result];
}
#pragma mark 基础请求
+(void)baseInterface:(NSString *)interface postData:(id)postData callBack:(kGetDataEventHandler)_result{
    [MBProgressHUD showHUDAddedTo:[UIApplication sharedApplication].keyWindow animated:YES];
    NSString *urlStr = [NSString stringWithFormat:@"%@%@",kMainUrl,interface];
    NSURL *url = [NSURL URLWithString:urlStr];
    NSMutableURLRequest *mr = [NSMutableURLRequest requestWithURL:url];
    if(postData){
        mr.HTTPMethod = @"POST";
        NSMutableDictionary *muDic = [postData mutableCopy];
        //获取&设置timestamp
        muDic[@"timestamp"] = [self getTimeStamp];
        //获取&设置sign
        NSString *sign = [self getSignWithDic:muDic interface:interface];
        muDic[@"sign"] = sign;
        NSString *postJson = [self getJsonStrWithDic:muDic];
        mr.HTTPBody = [postJson dataUsingEncoding:NSUTF8StringEncoding];
        [mr setValue:@"application/json" forHTTPHeaderField:@"Content-Type"];
    }else{
        mr.HTTPMethod = @"GET";
    }
    mr.timeoutInterval = TimeOutSec;
    [NSURLConnection sendAsynchronousRequest:mr queue:[NSOperationQueue mainQueue] completionHandler:^(NSURLResponse * _Nullable response, NSData * _Nullable data, NSError * _Nullable connectionError) {
        [MBProgressHUD hideHUDForView:[UIApplication sharedApplication].keyWindow animated:YES];
        if (connectionError) {
            _result(NO,connectionError);
        }else{
            NSString *dataStr = [[NSString alloc] initWithData:data encoding:NSUTF8StringEncoding];
            NSData *reData = [dataStr dataUsingEncoding:NSUTF8StringEncoding];
            _result(YES,[NSJSONSerialization JSONObjectWithData:reData options:NSJSONReadingMutableLeaves error:nil]);
        }
    }];
}

#pragma mark 字典转json
+(NSString *)getJsonStrWithDic:(NSDictionary *)dic{
    NSError *error;
    NSData *jsonData = [NSJSONSerialization dataWithJSONObject:dic options:NSJSONWritingPrettyPrinted error:&error];
    NSString *jsonString;
    if (!jsonData) {
        NSLog(@"%@",error);
    }else{
        jsonString = [[NSString alloc]initWithData:jsonData encoding:NSUTF8StringEncoding];
    }
    NSMutableString *mutStr = [NSMutableString stringWithString:jsonString];
    NSRange range = {0,jsonString.length};
    [mutStr replaceOccurrencesOfString:@" " withString:@"" options:NSLiteralSearch range:range];
    NSRange range2 = {0,mutStr.length};
    [mutStr replaceOccurrencesOfString:@"\n" withString:@"" options:NSLiteralSearch range:range2];
    return mutStr;
}
#pragma mark json转字典
+ (NSDictionary *)getDicWithStr:(NSString *)str {
    if (str == nil) {
        return @{};
    }
    NSData *data = [str dataUsingEncoding:NSUTF8StringEncoding];
    NSDictionary *dic = [NSJSONSerialization JSONObjectWithData:data options:NSJSONReadingAllowFragments error:nil];
    return dic;
}

//获取sign
+(NSString *)getSignWithDic:(NSDictionary *)dic interface:(NSString *)interface{
    //将请求体中的key按照a-z排列
    NSArray *sortedKeys = [[dic allKeys] sortedArrayUsingSelector: @selector(compare:)];
    NSString *sumStr = @"";
    //请求体中排除timestamp，并且按照key+value拼接成一个字符串
    for (NSString *key in sortedKeys) {
        if(![key isEqualToString:@"timestamp"]){
            NSObject *value = [dic valueForKey:key];
            NSString *valueStr = [NSString stringWithFormat:@"%@",value];
            sumStr = [sumStr stringByAppendingString:[NSString stringWithFormat:@"%@%@",key,valueStr]];
        }
    }
    //设计自己的sign签名规则
    //mysign$#@+sumStr(按照key+value拼接成一个字符串)+interface(接口路径:/login)+timestamp+csjnjksadh，然后md5加密
    sumStr = [NSString stringWithFormat:@"mysign$#@%@%@%@csjnjksadh",interface,sumStr,dic[@"timestamp"]];
    NSString *sign = [EncryptionTool md5Hex:[NSString stringWithFormat:@"%@",sumStr]];
    return sign;
}

//获取timestamp
+ (NSString *)getTimeStamp{
    NSDate *now = [NSDate date];
    NSString *timeStamp = [NSString stringWithFormat:@"%ld", (long)([now timeIntervalSince1970] * 1000)];
    return timeStamp;
}

@end
