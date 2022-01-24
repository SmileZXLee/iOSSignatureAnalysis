# iOSSignatureAnalysis

## Sign加密

### 概述&原理

【简述】当客户端像服务端发起请求时，以`POST`请求为例，如果提交的请求体内容未经过加密，请求可能存在被篡改的危险，即使是`https请求`也是如此（`https`抓包、修改请求只需要信任根证书即可）。可以通过众多代理抓包、网卡抓包的程序对请求进行拦截，修改请求内容或是使用程序模拟客户端请求发送，达到仿造请求、脱机请求等目的。例如抢购、秒杀类业务；以及一些要求客户端信息准确的业务（如打卡等）；应该对请求进行加密，例如使用aes对整个请求体进行对称加密、使用`sign`对请求体进行签名等。以下介绍`sign`签名的大致流程，因为`aes加密`流程相对比较简单，后续也会在密码加密中简要说明。

* ① 对请求体中的所有参数的key根据`ASCII码`的顺序排序（a-z），然后根据`key=value&key=value`拼接成一个字符串；如请求体为`{"password":"123456","timestamp":"1642765564000","account":"zxlee"}`，经过处理后为`account=zxlee&password=123456&timestamp=1642765564000`。
* ② 对上方`account=zxlee&password=123456&timestamp=1642765564000`进行`md5`加密，获得一串唯一的不可逆的16位或32位字符串。将计算出的`md5`加密后的字符串放在请求体或请求头中传给服务端。
* ③ 服务端在获取到请求体后，重复①、②中客户端的操作，根据请求体中的参数计算出`sign`值，与客户端传过来的`sign`进行比较，若不相等，则认为这个请求不合法，不进行任何业务操作，直接响应错误信息。
* ④ 若客户端发送的请求被篡改了，例如password被修改为了45678，则服务端实际上是对`account=zxlee&password=45678&timestamp=1642765564000`进行`md5`，则计算出来的`sign`值必定和客户端传过来的`sign`不相等，则此请求无效。

【进阶①：加盐】此时大家可能就在想了，我们完全可以仿造客户端的签名，自己计算sign值一并传给服务端，就可以绕过这个验证了。确实如此，因为我们已经知道了`sign`校验的基本流程和规则，但是事实上`sign`签名中`md5`之前的值并不是需要固定使用`key=value&key=value`拼接，只需要客户端与服务端私下约定好规则即可，例如可以在前后拼接约定好的字符串`73281937jjdsa key=value&key=value dsjahdjsah`，或者对`md5`进行加盐操作，这样攻击者希望仅仅通过抓包和自己尝试生成sign的梦想就完全破灭了。

【进阶②：添加时间戳，防止请求重放】在上述示例中，我们添加了`timestamp`这个时间戳，它的作用就是防止`请求重放`；通过上述的分析我们发现确实达到了可以防止请求体中的内容被篡改的问题，可以很大程度保证客户端数据的真实性，但是遇到类似抢购、秒杀业务的时候我们需要思考一个问题：当我们需要通过程序来抢购一个商品时，实际上不需要仿造任何请求，只需要通过抓包抓到`提交商品订单`的请求，然后通过程序不断重放，例如在1秒内请求10次，就可以获得远胜于手动点击的抢购速度，这对于一般的用户是不公平的，对服务器的负担也会大大增加。服务端可以通过`nginx`等对相同ip的请求次数加以限制，但是又有`ip池`等反制措施，所以对请求重放的限制也是必须的。而在添加`timestamp`参数后，客户端获取当前`timestamp`一并传给服务端，服务端只需要将校验相等的`sign`存在缓存中，并且在下一次请求时，判断`sign`是否在之前缓存的`sign`中即可。若在之前缓存的`sign`中，则直接响应错误信息。因正常的客户端每次请求都会生成最新的毫秒级的`timestamp`，则不会受任何影响（因为每次生成的`sign`必然不同），但通过`请求重放`方式提交的请求将被视为无效请求。

## AES加密

`aes`为`对称加密`，即加密和解密的密钥是相同的，客户端可以和服务端私下约定好一个密钥，然后客户端通过这个密钥对请求体进行加密，服务端通过这个密钥进行解密，若服务端能正常解密，则认为这是一个有效请求，通过`aes`加密可以有效防止请求被篡改，因为通过抓包看到的是`aes`加密之后的密文，抓包者不知道密钥的情况下无法获得明文信息，也无法修改明文内容。`aes`加密后的内容一般需要进行`base64`处理，因为有些`aes`加密后的字符串是不可读的。

## MD5加密

`md5`加密是一种`不可逆的加密`，也就是明文通过`md5`加密后获得密文后，无法通过密文解密获得明文，且相同明文加密后获得的密文必定相同且唯一，所以`md5`一般也用作密码加密（这就是为什么大多数网站只能提供"重置密码功能"而不能提供"查询密码"功能的原因，因为即使是开发者也不知道用户的明文密码是什么，服务端验证密码也只是对比`md5`之后的密码）和sign加密（因`md5`是不可逆并且唯一的，所以可以避免泄露sign签名的规则，并且可以保证前后端计算出的sign的一致性）。

但是`md5`也不是完全不可逆的，一些网站也推出了`md5`解密功能，但是实际基本都是使用`暴力破解字典`的方案，例如`123456`通过`md5`加密后的结果为`49ba59abbe56e057`，则已知密文为`49ba59abbe56e057`可以推算出明文为`123456`。因此密码不宜过于简单，如果是字母+数字的情况下，破解就几乎不可能。近年有报道指明`md5`已可逆、已不再安全，但是目前而言`md5`依然被广泛应用在各个需要加密的场景中，总体还是依旧可靠的。

## 实现sign签名+密码aes加密(示例)

* ios App+springboot登录接口sign签名+密码aes加密示例

## iOS App

* 在`LoginViewController`的点击登录按钮事件中，请求登录接口

  ```objective-c
  //点击了登录按钮
  - (IBAction)loginAction:(id)sender {
      NSString *account = self.accountTf.text;
      NSString *password = self.pwdTf.text;
      if(account.length && password.length){
          //对密码进行aes加密，key是xsahdjsad890dsaf
          password = [EncryptionTool aesEncrypt:password key:@"xsahdjsad890dsaf"];
          //发送登录请求
          [HttpRequest postInterface:@"/login" postData:@{@"account":account,@"password":password} callBack:^(BOOL result, id  _Nonnull data) {
              if(result && data){
                  int code = [data[@"code"] intValue];
                  if(code == 0){
                      //登录成功
                  }
              }
          }];
      }
  }
  ```

* 在`HttpRequest`的`postInterface`方法中获取sign和timestamp

  ```objective-c
  + (void)postInterface:(NSString *)interface postData:(id)postData callBack:(kGetDataEventHandler)_result {
      NSString *urlStr = [NSString stringWithFormat:@"%@%@",kMainUrl,interface];
      NSURL *url = [NSURL URLWithString:urlStr];
      NSMutableURLRequest *mr = [NSMutableURLRequest requestWithURL:url];
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
      mr.timeoutInterval = TimeOutSec;
      [NSURLConnection sendAsynchronousRequest:mr queue:[NSOperationQueue mainQueue] completionHandler:^(NSURLResponse * _Nullable response, NSData * _Nullable data, NSError * _Nullable connectionError) {
          if (connectionError) {
              _result(NO,connectionError);
          }else{
              NSString *dataStr = [[NSString alloc] initWithData:data encoding:NSUTF8StringEncoding];
              NSData *reData = [dataStr dataUsingEncoding:NSUTF8StringEncoding];
              _result(YES,[NSJSONSerialization JSONObjectWithData:reData options:NSJSONReadingMutableLeaves error:nil]);
          }
      }];
  }
  ```

* 在`HttpRequest`的`getSignWithDic`方法中计算sign

  ```objective-c
  + (NSString *)getSignWithDic:(NSDictionary *)dic interface:(NSString *)interface {
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
      //mysign$#@+interface(接口路径:/login)+sumStr(按照key+value拼接成一个字符串)+timestamp+csjnjksadh，然后md5加密
      sumStr = [NSString stringWithFormat:@"mysign$#@%@%@%@csjnjksadh",interface,sumStr,dic[@"timestamp"]];
      NSString *sign = [EncryptionTool md5Hex:[NSString stringWithFormat:@"%@",sumStr]];
      return sign;
  }
  ```

## JAVA后端接口

* 在`LoginController`中接收`/login`请求

  ```java
  @RestController
  @RequestMapping("/api/v1/")
  public class LoginController {
      @RequestMapping("/login")
      public CommonResponse login(@RequestBody LoginVO vo) {
          System.out.println("请求参数=> " + vo.toString());
  
          //签名校验
          //一般放在拦截器/过滤器中统一处理，此处为了方便直接写在控制器中
          if(!SignUtils.checkSign(vo,"/login")){
              return new CommonResponse().error("签名校验失败");
          }
  
          String account = vo.getAccount();
          String password = vo.getPassword();
          //----------begin账号和密码判空操作-----------
          if(null == account || account.isEmpty()){
              return new CommonResponse().error("账号不能为空");
          }
          if(null == password || password.isEmpty()){
              return new CommonResponse().error("密码不能为空");
          }
          //----------end-----------
  
          //密码aes解密
          try {
              password = AESUtils.decrypt(password,"xsahdjsad890dsaf");
          } catch (Exception e) {
              e.printStackTrace();
              return new CommonResponse().error("密码解密失败");
          }
  
          //对账号密码进行简单的校验
          //账号为：zxlee，密码为123456时，可以登录成功
          if(!"zxlee".equals(account)){
              return new CommonResponse().error("用户名不存在");
          }
  
          if(!"123456".equals(password)){
              return new CommonResponse().error("密码错误");
          }
  
          return new CommonResponse("登录成功").success();
      }
  }
  ```

* 在`SignUtils`中计算和验证sign

  ```java
  public class SignUtils {
      //用于在内存中缓存合法的sign，实际项目中建议存在redis中或用Spring Cache之类的进行管理
      static ArrayList<String> signCahceArr = new ArrayList<>();
  
      /**
      * @Description: 计算签名
      * @Param: [vo, inter]
      * @return: java.lang.String
      * @Author: zxlee
      * @Date: 2022/1/21
      */
      public static String getSign(CommonVO vo,String inter){
          String result = "";
          Map<String,Object> map = (Map<String,Object>) JSON.toJSON(vo);
          Set set = map.keySet();
          Object[] arr = set.toArray();
          Arrays.sort(arr);
          for(Object key : arr){
              if(!"timestamp".equals(key) && !"sign".equals(key)){
                  result += key + map.get(key).toString();
              }
          }
          result = "mysign$#@" + inter + result + map.get("timestamp") + "csjnjksadh";
          return DigestUtils.md5DigestAsHex(result.getBytes());
      }
  
      /**
      * @Description: 验证签名是否合法
      * @Param: [vo, inter]
      * @return: java.lang.Boolean
      * @Author: zxlee
      * @Date: 2022/1/21
      */
      public static Boolean checkSign(CommonVO vo,String inter){
          String sign = vo.getSign();
          //如果入参中sign不存在，直接返回false
          if(null == sign || sign.isEmpty()){
              return false;
          }
          //如果signCahceArr中已经存在此sign，则直接返回false，可有效避免请求重放
          if(signCahceArr.contains(sign)){
              return false;
          }
          //如果入参中sign不存在，直接返回false
          String calcSign = getSign(vo,inter);
          Boolean equals = calcSign.equals(sign);
          if(equals){
              //如果签名验证通过，将合法的sign存到缓存中，因为添加了timestamp参数，可以正常请求下保证同一客户端每次请求sign必定不同
              //若考虑高并发情况，建议根据ip区分一下sign
              signCahceArr.add(sign);
          }
          return equals;
      }
  }
  ```

## 验证

* 运行iOS App，输入账号密码，点击登录，登录流程正常。

* 开启`Charles`进行全局代理抓包，重复上述步骤，拦截到登录请求

  请求URL：http://api.zxlee.cn:6303/api/v1/login

  请求体：

  ```json
  {
    "password": "cbBIs8XOZJ2L5YjfuaOLAQ==",
    "account": "zxlee",
    "timestamp": "1642929374691",
    "sign": "469751ce43abf684e8fbf6786d8343b0"
  }
  ```

  响应：

  ```json
  {
    "message": "success",
    "code": 0,
    "data": "登录成功"
  }
  ```

  修改请求体内容，重新提交请求，响应：

  ```json
  {
    "message": "签名校验失败",
    "code": 400,
    "data": null
  }
  ```

  在`Charles`中右键请求，点击`Repeat`进行请求重放（不修改任何参数），响应：

  ```json
  {
    "message": "签名校验失败",
    "code": 400,
    "data": null
  }
  ```

  经过测试，各项功能达到预期要求。

# 逆向分析

### 【目的&思路】

* 【目的】通过逆向分析破解`sign`签名和`aes`加密
* 【思路】破解`sign`签名的关键就是分析清楚`md5`之前的字符串是根据何种规则拼接的，然后根据这个规则拼接参数然后进行md5加密即可。破解`ase`加密的关键是获取”密钥“。二者的核心都是拦截加密函数，破解`sign`签名通过拦截`md5`加密函数获取`md5`之前的字符串、`aes`加密通过拦截加密函数获取形参中的key。
* 【说明】仅对逆向思路作简要说明，具体代码请查看demo：[HookApp](https://github.com/SmileZXLee/iOSSignatureAnalysis/tree/main/HookApp)

## 【方案1】函数hook(class-dump+Logos)

* ① 通过`class-dump`导出`Target.app`（将`.ipa`后缀修改为`.zip`后解压）的[头文件](https://github.com/SmileZXLee/iOSSignatureAnalysis/tree/main/Headers)，查看头文件中的内容，寻找加密的工具类，可以发现一个名为`EncryptionTool.h`的头文件，查看文件内容：

  ```objective-c
  #import <objc/NSObject.h>
  
  @interface EncryptionTool : NSObject
  {
  }
  
  + (id)AES128Decrypt:(id)arg1 key:(id)arg2;
  + (id)AES128Encrypt:(id)arg1 key:(id)arg2;
  + (id)md5Hex:(id)arg1;
  + (id)aesDecryptWithBase64:(id)arg1 key:(id)arg2;
  + (id)aesEncrypt:(id)arg1 key:(id)arg2;
  
  @end
  ```

  可以观察到这个工具类中有`+ (id)md5Hex:(id)arg1`方法，根据命名可以猜测这个函数是用于`md5`加密的，我们通过`Logos`hook这个函数：

  ```objective-c
  %hook EncryptionTool
  + (id)md5Hex:(id)arg1{
      NSLog(@"md5加密之前的明文：%@",arg1);
      return %orig;
  }
  %end
  ```

  注入后重新运行后输入账号密码点击登录并查看打印：

  ```
  TargetApp[18861:4954135] md5加密之前的明文：mysign$#@/loginaccountzxleepasswordcbBIs8XOZJ2L5YjfuaOLAQ==1642953195950csjnjksadh
  ```

  并通过抓包查看请求体内容，与上方`md5`之前的明文进行对照：

  ```json
  {
    "password": "cbBIs8XOZJ2L5YjfuaOLAQ==",
    "account": "zxlee",
    "timestamp": "1642953195950",
    "sign": "bc7c62f09da86b2ee0c28476a70be709"
  }
  ```

  从上方可以推测出`sign`签名的规则为：mysign$#@+interface(接口路径:/login)+sumStr(按照key+value拼接成一个字符串)+timestamp+csjnjksadh。此时`sign`签名就已被破解。

* ② `EncryptionTool.h`中有两个aes相关的类，不清楚实际上用的是哪个，因此两个都hook一下：

  ```objective-c
  %hook EncryptionTool
  + (id)AES128Encrypt:(id)arg1 key:(id)arg2{
      NSLog(@"aes加密之前的明文：%@；aes的key：%@",arg1,arg2);
      return %orig;
  }
  
  + (id)aesEncrypt:(id)arg1 key:(id)arg2{
      NSLog(@"aes加密之前的明文：%@；aes的key：%@",arg1,arg2);
      return %orig;
  }
  %end
  ```

  注入后重新运行后输入账号密码点击登录并查看打印：

  ```
  TargetApp[18861:4954135] aes加密之前的明文：123456；aes的key：xsahdjsad890dsaf
  ```

  因此`aes`加密的key为`xsahdjsad890dsaf`，至于具体是那种`aes`加密的模式，只需要通过在线`aes`加密工具逐一验证一下即可。

## 【方案2】方法追踪(class-dump+monkeyDev)

* 【ps】需要导入[ZXHookUtil](https://github.com/SmileZXLee/ZXHookUtil)

* ① 与【方案1】一致，通过`class-dump`导出头文件，发现`EncryptionTool.h`这个头文件，通过：

  ```objective-c
  [ZXHookUtil addClassTrace:@"EncryptionTool"];
  ```

  添加方法追踪，监视`EncryptionTool`这个类的方法调用情况，运行后输入账号密码点击登录并查看打印：

  ```objective-c
  ┌ +[Call][EncryptionTool aesEncrypt:123456 key:xsahdjsad890dsaf]
  │ ┌ +[Call][EncryptionTool AES128Encrypt:123456 key:xsahdjsad890dsaf]
  │ └ +[Return]cbBIs8XOZJ2L5YjfuaOLAQ==
  └ +[Return]cbBIs8XOZJ2L5YjfuaOLAQ==
  ┌ +[Call][EncryptionTool md5Hex:mysign$#@/loginaccountzxleepasswordcbBIs8XOZJ2L5YjfuaOLAQ==1642955401392csjnjksadh]
  └ +[Return]cf1e6b5ddb2b51764b7e44a9b1fd080e
  ```

  由以上的打印可以看到方法调用关系，一组通过`[`连接起来的就是方法调用的起始和终止位置，可以看到在点击登录按钮之后`EncryptionTool aesEncrypt`方法内又调用了`EncryptionTool AES128Encrypt`，并且我们可以清晰看到参数和返回值，`sign`签名和`aes`加密均已破解。

## 【方案3】UI分析+IDA反编译(monkeyDev+IDA)

* 【ps】需要导入[ZXHookUtil](https://github.com/SmileZXLee/ZXHookUtil)

* ① 在初始化时书写代码：

  ```objective-c
  //延时1秒
  dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(1 * NSEC_PER_SEC)), dispatch_get_main_queue(), ^{
    //添加全局的红色按钮
    [ZXHookUtil addBtnCallBack:^(UIButton *button) {
      //在这个红色按钮的点击事件中，打印当前显示的控制器
      NSLog(@"当前控制器--%@",[ZXHookUtil getTopVC]);
    }];
  });
  ```

  点击红色按钮，查看打印：

  ```
  TargetApp[1359:165053] 当前控制器--<LoginViewController: 0x147e12d60>
  ```

  可知，当前控制器为`LoginViewController`。

* ② 继续在初始化的地方添加对`LoginViewController`的方法追踪：

  ```objective-c
  [ZXHookUtil addClassTrace:@"LoginViewController"];
  ```

  重新运行项目，输入账号密码后点击登录按钮：

  ```objective-c
  ┌ -[Call][<LoginViewController: 0x10530fab0> loginAction:<UIButton: 0x105314af0>]
  │ ┌ -[Call][<LoginViewController: 0x10530fab0> accountTf]
  │ └ -[Return]<UITextField: 0x10582b000;>
  │ ┌ -[Call][<LoginViewController: 0x10530fab0> pwdTf]
  │ └ -[Return]<UITextField: 0x106031c00;>
  └ -[Return]void
  ```

  由上方打印可以看出，在点击登录按钮之后，调用了`LoginViewController`的`loginAction`方法。我们通过`IDA`对`loginAction`方法中的代码进行反编译。

* ③ 我们在`IDA`中导入`TargetApp.app`内的可执行文件，并找到`-[LoginViewControll loginAction:]`方法，通过`F5`直接查看反编译后的伪代码：

  ```objective-c
  void __cdecl -[LoginViewController loginAction:](LoginViewController *self, SEL a2, id a3)
  {
    LoginViewController *v3; // x19
    void *v4; // x0
    void *v5; // x20
    UITextField *v6; // x0
    void *v7; // x0
    void *v8; // x22
    void *v9; // x0
    void *v10; // x20
    UITextField *v11; // x0
    void *v12; // x0
    void *v13; // x24
    void *v14; // x0
    void *v15; // x22
    struct objc_object *v16; // x0
    __int64 v17; // x21
    void *v18; // x0
    __int64 v19; // x23
    void *v20; // x0
    void *v21; // x19
    void **v22; // [xsp+0h] [xbp-80h]
    __int64 v23; // [xsp+8h] [xbp-78h]
    __int64 (__fastcall *v24)(); // [xsp+10h] [xbp-70h]
    void *v25; // [xsp+18h] [xbp-68h]
    LoginViewController *v26; // [xsp+20h] [xbp-60h]
    const __CFString *v27; // [xsp+28h] [xbp-58h]
    const __CFString *v28; // [xsp+30h] [xbp-50h]
    void *v29; // [xsp+38h] [xbp-48h]
    __int64 v30; // [xsp+40h] [xbp-40h]
  
    v3 = self;
    v4 = objc_msgSend(self, "view", a3);
    v5 = (void *)objc_retainAutoreleasedReturnValue(v4);
    objc_msgSend(v5, "endEditing:", 1LL);
    objc_release(v5);
    v6 = -[LoginViewController accountTf](v3, "accountTf");
    v7 = (void *)objc_retainAutoreleasedReturnValue(v6);
    v8 = v7;
    v9 = objc_msgSend(v7, "text");
    v10 = (void *)objc_retainAutoreleasedReturnValue(v9);
    objc_release(v8);
    v11 = -[LoginViewController pwdTf](v3, "pwdTf");
    v12 = (void *)objc_retainAutoreleasedReturnValue(v11);
    v13 = v12;
    v14 = objc_msgSend(v12, "text");
    v15 = (void *)objc_retainAutoreleasedReturnValue(v14);
    objc_release(v13);
    if ( objc_msgSend(v10, "length") && objc_msgSend(v15, "length") )
    {
      v16 = +[EncryptionTool aesEncrypt:key:](
              &OBJC_CLASS___EncryptionTool,
              "aesEncrypt:key:",
              v15,
              CFSTR("xsahdjsad890dsaf"));
      v17 = objc_retainAutoreleasedReturnValue(v16);
      objc_release(v15);
      v27 = CFSTR("account");
      v28 = CFSTR("password");
      v29 = v10;
      v30 = v17;
      v18 = objc_msgSend(&OBJC_CLASS___NSDictionary, "dictionaryWithObjects:forKeys:count:", &v29, &v27, 2LL);
      v19 = objc_retainAutoreleasedReturnValue(v18);
      v22 = _NSConcreteStackBlock;
      v23 = 3254779904LL;
      v24 = sub_10001240C;
      v25 = &unk_1000184C8;
      v26 = v3;
      +[HttpRequest postInterface:postData:callBack:](
        &OBJC_CLASS___HttpRequest,
        "postInterface:postData:callBack:",
        CFSTR("/login"),
        v19,
        &v22,
        _NSConcreteStackBlock,
        3254779904LL,
        sub_10001240C,
        &unk_1000184C8,
        v3);
      objc_release(v19);
      v15 = (void *)v17;
    }
    else
    {
      v20 = objc_msgSend(v3, "view");
      v21 = (void *)objc_retainAutoreleasedReturnValue(v20);
      objc_msgSend(v21, "makeToast:duration:position:", CFSTR("账号或密码不得为空"), off_10001E658, 1.5);
      objc_release(v21);
    }
    objc_release(v15);
    objc_release(v10);
  }
  ```

  从上方伪代码中我们可以找到一段关键的代码：

  ```objective-c
  v16 = +[EncryptionTool aesEncrypt:key:](
    &OBJC_CLASS___EncryptionTool,
    "aesEncrypt:key:",
    v15,
    CFSTR("xsahdjsad890dsaf"));
  ```

  其中括号内的第一个参数`&OBJC_CLASS___EncryptionTool`代表方法的类名，第二个参数`"aesEncrypt:key:"`代表的是方法名，第三、第四个参数分别代表`aesEncrypt:key:`这个方法的两个入参，`v15`通过上文推倒可以知道是用户输入的密码文本，`CFSTR("xsahdjsad890dsaf")`就是这个密码`aes`加密的key。至此，我们成功获取到`aes`的key。

* ④ 猜测sign签名代码是在封装的请求的内部，从上方伪代码可以看出，登录事件中，调用了`+[HttpRequest postInterface:postData:callBack:]`进行请求，我们继续查看这个方法中的伪代码：

  ```objective-c
  void __cdecl +[HttpRequest postInterface:postData:callBack:](HttpRequest_meta *self, SEL a2, id a3, id a4, id a5)
  {
    objc_msgSend(self, "baseInterface:postData:callBack:", a3, a4, a5);
  }
  ```

  可以看出，`[HttpRequest postInterface:postData:callBack:]`方法中直接调用了`[HttpRequest baseInterface:postData:callBack:]`方法，我们继续查看`[HttpRequest baseInterface:postData:callBack:]`中的伪代码：

  ```objective-c
  void __cdecl +[HttpRequest baseInterface:postData:callBack:](HttpRequest_meta *self, SEL a2, id a3, id a4, id a5)
  {
    id v5; // x21
    id v6; // x20
    HttpRequest_meta *v7; // x25
    __int64 v8; // x19
    __int64 v9; // x1
    void *v10; // x20
    __int64 v11; // x1
    __int64 v12; // x21
    void *v13; // x0
    void *v14; // x0
    void *v15; // x23
    void *v16; // x0
    __int64 v17; // x0
    __int64 v18; // x24
    struct objc_object *v19; // x0
    void *v20; // x0
    __int64 v21; // x0
    __int64 v22; // x22
    void *v23; // x0
    __int64 v24; // x0
    __int64 v25; // x23
    void *v26; // x0
    void *v27; // x0
    void *v28; // x24
    void *v29; // x26
    void *v30; // x0
    __int64 v31; // x27
    void *v32; // x0
    __int64 v33; // x27
    void *v34; // x0
    void *v35; // x0
    void *v36; // x25
    void *v37; // x0
    __int64 v38; // x28
    void *v39; // x0
    __int64 v40; // x26
    __int64 v41; // x1
    __int64 v42; // x21
    void **v43; // [xsp+18h] [xbp-78h]
    __int64 v44; // [xsp+20h] [xbp-70h]
    __int64 (__fastcall *v45)(); // [xsp+28h] [xbp-68h]
    void *v46; // [xsp+30h] [xbp-60h]
    __int64 v47; // [xsp+38h] [xbp-58h]
  
    v5 = a5;
    v6 = a4;
    v7 = self;
    v8 = objc_retain(a3, a2);
    v10 = (void *)objc_retain(v6, v9);
    v12 = objc_retain(v5, v11);
    v13 = objc_msgSend(&OBJC_CLASS___UIApplication, "sharedApplication");
    v14 = (void *)objc_retainAutoreleasedReturnValue(v13);
    v15 = v14;
    v16 = objc_msgSend(v14, "keyWindow");
    v17 = objc_retainAutoreleasedReturnValue(v16);
    v18 = v17;
    v19 = +[MBProgressHUD showHUDAddedTo:animated:](&OBJC_CLASS___MBProgressHUD, "showHUDAddedTo:animated:", v17, 1LL);
    objc_unsafeClaimAutoreleasedReturnValue(v19);
    objc_release(v18);
    objc_release(v15);
    v20 = objc_msgSend(
            &OBJC_CLASS___NSString,
            "stringWithFormat:",
            CFSTR("%@%@"),
            CFSTR("http://api.zxlee.cn:6303/api/v1"),
            v8);
    v21 = objc_retainAutoreleasedReturnValue(v20);
    v22 = v21;
    v23 = objc_msgSend(&OBJC_CLASS___NSURL, "URLWithString:", v21);
    v24 = objc_retainAutoreleasedReturnValue(v23);
    v25 = v24;
    v26 = objc_msgSend(&OBJC_CLASS___NSMutableURLRequest, "requestWithURL:", v24);
    v27 = (void *)objc_retainAutoreleasedReturnValue(v26);
    v28 = v27;
    if ( v10 )
    {
      objc_msgSend(v27, "setHTTPMethod:", CFSTR("POST"));
      v29 = objc_msgSend(v10, "mutableCopy");
      v30 = objc_msgSend(v7, "getTimeStamp");
      v31 = objc_retainAutoreleasedReturnValue(v30);
      objc_msgSend(v29, "setObject:forKeyedSubscript:", v31, CFSTR("timestamp"));
      objc_release(v31);
      //这里给v32赋值，就是给sign赋值，我们可以发现这个v32是通过一个方法的返回值赋值，这个方法的类名为v7，方法名为getSignWithDic:interface:，继续往上推导，可以发现v7=self，也就是当前类，所以sign是通过[HttpRequest getSignWithDic:interface:]计算出来的，因此我们继续查看[HttpRequest getSignWithDic:interface:]的伪代码
      v32 = objc_msgSend(v7, "getSignWithDic:interface:", v29, v8);
      //v33=v32
      v33 = objc_retainAutoreleasedReturnValue(v32);
      //设置sign，v33就是最终的sign
      objc_msgSend(v29, "setObject:forKeyedSubscript:", v33, CFSTR("sign"));
      v34 = objc_msgSend(v7, "getJsonStrWithDic:", v29);
      v35 = (void *)objc_retainAutoreleasedReturnValue(v34);
      v36 = v35;
      v37 = objc_msgSend(v35, "dataUsingEncoding:", 4LL);
      v38 = objc_retainAutoreleasedReturnValue(v37);
      objc_msgSend(v28, "setHTTPBody:", v38);
      objc_release(v38);
      objc_msgSend(v28, "setValue:forHTTPHeaderField:", CFSTR("application/json"), CFSTR("Content-Type"));
      objc_release(v36);
      objc_release(v33);
      objc_release(v29);
    }
    else
    {
      objc_msgSend(v27, "setHTTPMethod:", CFSTR("GET"));
    }
    objc_msgSend(v28, "setTimeoutInterval:", 10.0);
    v39 = objc_msgSend(&OBJC_CLASS___NSOperationQueue, "mainQueue");
    v40 = objc_retainAutoreleasedReturnValue(v39);
    v43 = _NSConcreteStackBlock;
    v44 = 3254779904LL;
    v45 = sub_100008518;
    v46 = &unk_100018378;
    v47 = v12;
    v42 = objc_retain(v12, v41);
    objc_msgSend(&OBJC_CLASS___NSURLConnection, "sendAsynchronousRequest:queue:completionHandler:", v28, v40, &v43);
    objc_release(v40);
    objc_release(v47);
    objc_release(v42);
    objc_release(v28);
    objc_release(v25);
    objc_release(v22);
    objc_release(v10);
    objc_release(v8);
  }
  ```

  从上方`objc_msgSend(v29, "setObject:forKeyedSubscript:", v33, CFSTR("sign"));`可以看出，这句代码在给请求体设置sign，我在这一行上方添加了注释，大家可以看一下。经过分析可以发现sign是通过`[HttpRequest getSignWithDic:interface:]`计算出来的，因此我们继续查看`[HttpRequest getSignWithDic:interface:]`的伪代码：

  ```objective-c
  //a3就是getSignWithDic:后方的入参，a4是interface:后方的入参
  id __cdecl +[HttpRequest getSignWithDic:interface:](HttpRequest_meta *self, SEL a2, id a3, id a4)
  {
    id v4; // x19
    void *v5; // x20
    __int64 v6; // x1
    void *v7; // x0
    void *v8; // x0
    void *v9; // x19
    void *v10; // x0
    __int64 v11; // x20
    __int64 v12; // x1
    void *v13; // x0
    void *v14; // x0
    void *v15; // x23
    __CFString *v16; // x26
    __int64 v17; // x25
    const __CFString *v18; // x21
    unsigned __int64 v19; // x19
    __int64 v20; // x27
    void *v21; // x0
    __int64 v22; // x0
    __int64 v23; // x28
    __CFString *v24; // x20
    void *v25; // x0
    __int64 v26; // x0
    const __CFString *v27; // x22
    __int64 v28; // x21
    void *v29; // x0
    __int64 v30; // x0
    __int64 v31; // x27
    void *v32; // x0
    __int64 v33; // x0
    void *v34; // x0
    __int64 v35; // x0
    __int64 v36; // x20
    void *v37; // x0
    __int64 v38; // x21
    void *v39; // x0
    __int64 v40; // x0
    __int64 v41; // x20
    struct objc_object *v42; // x0
    __int64 v43; // x19
    __int64 v44; // x0
    __int64 v46; // [xsp+20h] [xbp-160h]
    void *v47; // [xsp+30h] [xbp-150h]
    void *v48; // [xsp+48h] [xbp-138h]
    void *v49; // [xsp+58h] [xbp-128h]
    __int128 v50; // [xsp+60h] [xbp-120h]
    __int128 v51; // [xsp+70h] [xbp-110h]
    __int128 v52; // [xsp+80h] [xbp-100h]
    __int128 v53; // [xsp+90h] [xbp-F0h]
    char v54; // [xsp+A0h] [xbp-E0h]
    __int64 v55; // [xsp+120h] [xbp-60h]
  
    v4 = a4;
    //v5=a3
    v5 = (void *)objc_retain(a3, a2);
    //v46=v4
    v46 = objc_retain(v4, v6);
    //v47=v5
    v47 = v5;
    v7 = objc_msgSend(v5, "allKeys");
    v8 = (void *)objc_retainAutoreleasedReturnValue(v7);
    v9 = v8;
    v10 = objc_msgSend(v8, "sortedArrayUsingSelector:", "compare:");
    v11 = objc_retainAutoreleasedReturnValue(v10);
    objc_release(v9);
    v52 = 0u;
    v53 = 0u;
    v50 = 0u;
    v51 = 0u;
    v13 = (void *)objc_retain(v11, v12);
    v49 = v13;
    v14 = objc_msgSend(v13, "countByEnumeratingWithState:objects:count:", &v50, &v54, 16LL);
    if ( v14 )
    {
      v15 = v14;
      v16 = &stru_100018798;
      v17 = *(_QWORD *)v51;
      v18 = CFSTR("timestamp");
      do
      {
        v19 = 0LL;
        v48 = v15;
        do
        {
          if ( *(_QWORD *)v51 != v17 )
            objc_enumerationMutation(v49);
          v20 = *(_QWORD *)(*((_QWORD *)&v50 + 1) + 8 * v19);
          if ( !((unsigned __int64)objc_msgSend(*(void **)(*((_QWORD *)&v50 + 1) + 8 * v19), "isEqualToString:", v18) & 1) )
          {
            v21 = objc_msgSend(v47, "valueForKey:", v20);
            v22 = objc_retainAutoreleasedReturnValue(v21);
            v23 = v22;
            v24 = v16;
            v25 = objc_msgSend(&OBJC_CLASS___NSString, "stringWithFormat:", CFSTR("%@"), v22);
            v26 = objc_retainAutoreleasedReturnValue(v25);
            v27 = v18;
            v28 = v26;
            v29 = objc_msgSend(&OBJC_CLASS___NSString, "stringWithFormat:", CFSTR("%@%@"), v20, v26);
            v30 = objc_retainAutoreleasedReturnValue(v29);
            v31 = v30;
            v32 = objc_msgSend(v16, "stringByAppendingString:", v30);
            v16 = (__CFString *)objc_retainAutoreleasedReturnValue(v32);
            objc_release(v24);
            objc_release(v31);
            v33 = v28;
            v18 = v27;
            objc_release(v33);
            objc_release(v23);
            v15 = v48;
          }
          ++v19;
        }
        while ( v19 < (unsigned __int64)v15 );
        v15 = objc_msgSend(v49, "countByEnumeratingWithState:objects:count:", &v50, &v54, 16LL);
      }
      while ( v15 );
    }
    else
    {
      v16 = &stru_100018798;
    }
    objc_release(v49);
    //v34=v47[@"timestamp"]，因为v47就是传进来的dic，所以这里取的就是当前请求体中的时间戳
    v34 = objc_msgSend(v47, "objectForKeyedSubscript:", CFSTR("timestamp"));
    //v35=v34
    v35 = objc_retainAutoreleasedReturnValue(v34);
    v36 = v35;
    //v37=mysign$#+v46+v16+v35+csjnjksadh
    v37 = objc_msgSend(&OBJC_CLASS___NSString, "stringWithFormat:", CFSTR("mysign$#@%@%@%@csjnjksadh"), v46, v16, v35);
    //v38=v37
    v38 = objc_retainAutoreleasedReturnValue(v37);
    objc_release(v16);
    objc_release(v36);
    //v39=v38
    v39 = objc_msgSend(&OBJC_CLASS___NSString, "stringWithFormat:", CFSTR("%@"), v38);
    //v40=v39
    v40 = objc_retainAutoreleasedReturnValue(v39);
    v41 = v40;
    //这里对sign进行md5加密，因此加密之前的sign就是我们要的，即v40
    v42 = +[EncryptionTool md5Hex:](&OBJC_CLASS___EncryptionTool, "md5Hex:", v40);
    v43 = objc_retainAutoreleasedReturnValue(v42);
    objc_release(v41);
    objc_release(v38);
    objc_release(v49);
    objc_release(v46);
    v44 = objc_release(v47);
    if ( __stack_chk_guard == v55 )
      v44 = v43;
    return (id)_objc_autoreleaseReturnValue(v44);
  }
  ```

  通过分析上方伪代码（分析过程见上方代码中的注释）可以得出`sign`签名规则为：mysign$#@+interface(接口路径:/login)+sumStr(按照key+value拼接成一个字符串)+timestamp+csjnjksadh，然后md5加密。

* ⑤ 【总结】：使用`IDA`分析比其他方案繁琐得多，但是更可靠更严谨，但是一般情况是仍然推荐【方案1】和【方案2】。

## 待续...





