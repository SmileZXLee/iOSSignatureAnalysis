# iOSSignatureAnalysis

* iOSApp+springboot后端sign签名+aes加密流程已完成
* 逆向示例开发中

## 已实现功能

* 密码采用AES-128-ECB加密
* 请求体使用sign签名，防止篡改和请求重放

## Sign加密流程

### 概述&原理

【简述】当客户端像服务端发起请求时，以POST请求为例，如果提交的请求体内容未经过加密，请求可能存在被篡改的危险，即使是https请求也是如此（https抓包、修改请求只需要信任根证书即可）。可以通过众多代理抓包、网卡抓包的程序对请求进行拦截，修改请求内容或是使用程序模拟客户端请求发送，达到仿造请求、脱机请求等目的。例如抢购、秒杀类业务；以及一些要求客户端信息准确的业务（如打卡等）；应该对请求进行加密，例如使用aes对整个请求体进行对称加密、使用sign对请求体进行签名等。以下介绍sign签名的大致流程，因为aes加密流程相对比较简单，后续也会在密码加密中简要说明。

* ① 对请求体中的所有参数的key根据ASCII码的顺序排序（a-z），然后根据`key=value&key=value`拼接成一个字符串；如请求体为`{"password":"123456","timestamp":"1642765564000","account":"zxlee"}`，经过处理后为`account=zxlee&password=123456&timestamp=1642765564000`。
* ② 对上方`account=zxlee&password=123456&timestamp=1642765564000`进行md5加密，获得一串唯一的不可逆的16位或32位字符串。将计算出的md5加密后的字符串放在请求体或请求头中传给服务端。
* ③ 服务端在获取到请求体后，重复①、②中客户端的操作，根据请求体中的参数计算出sign值，与客户端传过来的sign进行比较，若不相等，则认为这个请求不合法，不进行任何业务操作，直接响应错误信息。
* ④ 若客户端发送的请求被篡改了，例如password被修改为了45678，则服务端实际上是对`account=zxlee&password=45678&timestamp=1642765564000`进行md5，则计算出来的sign值必定和客户端传过来的sign不相等，则此请求无效。

【进阶①：加盐】此时大家可能就在想了，我们完全可以仿造客户端的签名，自己计算sign值一并传给服务端，就可以绕过这个验证了。确实如此，因为我们已经知道了sign校验的基本流程和规则，但是事实上sign签名中md5之前的值并不是需要固定使用`key=value&key=value`拼接，只需要客户端与服务端私下约定好规则即可，例如可以在前后拼接约定好的字符串`73281937jjdsa key=value&key=value dsjahdjsah`，或者对md5进行加盐操作，这样攻击者希望仅仅通过抓包和自己尝试生成sign的梦想就完全破灭了。

<br>

【进阶②：添加时间戳，防止请求重放】在上述示例中，我们添加了timestamp这个时间戳，它的作用就是防止`请求重放`；通过上述的分析我们发现确实达到了可以防止请求体中的内容被篡改的问题，可以很大程度保证客户端数据的真实性，但是遇到类似抢购、秒杀业务的时候我们需要思考一个问题：当我们需要通过程序来抢购一个商品时，实际上不需要仿造任何请求，只需要通过抓包抓到`提交商品订单`的请求，然后通过程序不断重放，例如在1秒内请求10次，就可以获得远胜于手动点击的抢购速度，这对于一般的用户是不公平的，对服务器的负担也会大大增加。服务端可以通过`nginx`等对相同ip的请求次数加以限制，但是又有ip池等反制措施，所以对请求重放的限制也是必须的。

而在添加`timestamp`参数后，客户端获取当前`timestamp`一并传给服务端，服务端只需要将校验相等的sign存在缓存中，并且在下一次请求时，判断sign是否在之前缓存的sign中即可。若在之前缓存的sign中，则直接响应错误信息。因正常的客户端每次请求都会生成最新的毫秒级的`timestamp`，则不会受任何影响（因为每次生成的sign必然不同），但通过`请求重放`方式提交的请求将被视为无效请求。





