package cn.zxlee.signatureanalysistest.controller;

import cn.zxlee.signatureanalysistest.response.CommonResponse;
import cn.zxlee.signatureanalysistest.utils.AESUtils;
import cn.zxlee.signatureanalysistest.utils.SignUtils;
import cn.zxlee.signatureanalysistest.vo.LoginVO;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * @program: signature-analysis-test
 * @description: LoginController
 * @author: zxlee
 * @create: 2022-01-21
 **/
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
