package cn.zxlee.signatureanalysistest.response;

import lombok.Data;

/**
 * @program: signature-analysis-test
 * @description: CommonResponse
 * @author: zxlee
 * @create: 2022-01-21
 **/
@Data
public class CommonResponse<T> {
    static private Integer commonSuccessCode = 0;
    static private Integer commonErrorCode = 400;

    private String message;
    private Integer code;
    private T data;

    public CommonResponse(){

    }

    public CommonResponse(T data){
        this.data = data;
    }

    public CommonResponse<T> success(){
        this.code = commonSuccessCode;
        this.message = "success";
        return this;
    }

    public CommonResponse<T> error(String message){
        this.code = commonErrorCode;
        this.message = message;
        return this;
    }
}
