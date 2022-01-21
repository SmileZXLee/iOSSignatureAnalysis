//
//  ZXCodeFloor.m
//  ZXHookUtilDemoDylib
//
//  Created by 李兆祥 on 2019/3/10.
//  Copyright © 2019 李兆祥. All rights reserved.
//  书写业务代码
//  Github：https://github.com/SmileZXLee/ZXHookUtil

#import "ZXCodeFloor.h"

@implementation ZXCodeFloor
+(void)initAction{
    [ZXHookUtil addClassTrace:@"HttpRequest"];
    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(1 * NSEC_PER_SEC)), dispatch_get_main_queue(), ^{
        [ZXHookUtil addBtnCallBack:^(UIButton *button) {
            NSLog(@"当前控制器--%@",[ZXHookUtil getTopVC]);
        }];
    });
    
}
+(void)handleObj:(id)obj{
    
}
@end
