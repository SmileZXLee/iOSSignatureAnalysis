package cn.zxlee.signatureanalysistest.vo;

import lombok.Data;
import lombok.ToString;

/**
 * @program: signature-analysis-test
 * @description: LoginVO
 * @author: zxlee
 * @create: 2022-01-21
 **/
@ToString(callSuper = true)
@Data
public class LoginVO extends CommonVO {
    //用户账号
    private String account;
    //用户密码
    private String password;
}