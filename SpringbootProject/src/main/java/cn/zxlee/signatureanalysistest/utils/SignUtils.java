package cn.zxlee.signatureanalysistest.utils;

import cn.zxlee.signatureanalysistest.vo.CommonVO;
import com.alibaba.fastjson.JSON;
import org.springframework.util.DigestUtils;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Map;
import java.util.Set;

/**
 * @program: signature-analysis-test
 * @description: SignUtils
 * @author: zxlee
 * @create: 2022-01-21
 **/
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
