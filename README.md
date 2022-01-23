# iOSSignatureAnalysis

* iOSApp+springboot后端sign签名+aes加密流程已完成
* 逆向示例开发中

## 已实现功能

* 密码采用`AES-128-ECB`加密
* 请求体使用`sign`签名，防止篡改和请求重放

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
      //mysign$#@+sumStr(按照key+value拼接成一个字符串)+interface(接口路径:/login)+timestamp+csjnjksadh，然后md5加密
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

  从上方可以推测出`sign`签名的规则为：mysign$#@+sumStr(按照key+value拼接成一个字符串)+interface(接口路径:/login)+timestamp+csjnjksadh。此时`sign`签名就已被破解。

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

##【方案3】UI分析+IDA反编译(monkeyDev+IDA)



## 待续...





