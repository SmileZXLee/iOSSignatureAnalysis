//
//  ViewController.m
//  TargetApp
//
//  Created by 李兆祥 on 2022/1/20.
//

#import "ViewController.h"
#import "HttpRequest.h"
#import "EncryptionTool.h"
#import "UIView+Toast.h"
@interface ViewController ()
@property (weak, nonatomic) IBOutlet UITextField *accountTf;
@property (weak, nonatomic) IBOutlet UITextField *pwdTf;
@property (weak, nonatomic) IBOutlet UIButton *loginBtn;

@end

@implementation ViewController

- (void)viewDidLoad {
    [super viewDidLoad];
    self.loginBtn.clipsToBounds = YES;
    self.loginBtn.layer.cornerRadius = 10;
}


//点击了登录按钮
- (IBAction)loginAction:(id)sender {
    [self.view endEditing:YES];
    if([self noNull]){
        NSString *account = self.accountTf.text;
        NSString *password = [EncryptionTool aesEncrypt:self.pwdTf.text key:@"xsahdjsad890dsaf"];
        [HttpRequest postInterface:@"/login" postData:@{@"account":account,@"password":password} callBack:^(BOOL result, id  _Nonnull data) {
            if(result && data){
                
                int code = [data[@"code"] intValue];
                NSString *msg = data[@"message"];
                if(code == 0){
                    [self.view makeToast:@"登录成功" duration:1.5 position:CSToastPositionCenter];
                }else{
                    [self.view makeToast:msg duration:1.5 position:CSToastPositionCenter];
                }
            }else{
                [self.view makeToast:@"请求失败" duration:1.5 position:CSToastPositionCenter];
            }
        }];
    }else{
        [self.view makeToast:@"账号或密码不得为空" duration:1.5 position:CSToastPositionCenter];
    }
}

- (BOOL)noNull {
    return self.accountTf.text.length && self.pwdTf.text.length;
}

- (void)touchesBegan:(NSSet<UITouch *> *)touches withEvent:(UIEvent *)event {
    [self.view endEditing:YES];
}

@end
