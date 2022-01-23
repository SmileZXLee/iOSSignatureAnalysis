//
//  LoginViewController.m
//  TargetApp
//
//  Created by 李兆祥 on 2022/1/20.
//

#import "LoginViewController.h"
#import "HttpRequest.h"
#import "EncryptionTool.h"
#import "UIView+Toast.h"
@interface LoginViewController ()
@property (weak, nonatomic) IBOutlet UITextField *accountTf;
@property (weak, nonatomic) IBOutlet UITextField *pwdTf;
@property (weak, nonatomic) IBOutlet UIButton *loginBtn;

@end

@implementation LoginViewController

- (void)viewDidLoad {
    [super viewDidLoad];
    self.loginBtn.clipsToBounds = YES;
    self.loginBtn.layer.cornerRadius = 10;
}


//点击了登录按钮
- (IBAction)loginAction:(id)sender {
    [self.view endEditing:YES];
    NSString *account = self.accountTf.text;
    NSString *password = self.pwdTf.text;
    if(account.length && password.length){
        //对密码进行aes加密，key是xsahdjsad890dsaf
        password = [EncryptionTool aesEncrypt:password key:@"xsahdjsad890dsaf"];
        //发送登录请求
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

- (void)touchesBegan:(NSSet<UITouch *> *)touches withEvent:(UIEvent *)event {
    [self.view endEditing:YES];
}

@end
