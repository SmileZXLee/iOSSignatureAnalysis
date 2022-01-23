package cn.zxlee.signatureanalysistest.utils;

import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;
import java.util.Base64;

public class AESUtils {

    private static final String AES_ALGORITHM = "AES/ECB/PKCS5Padding";

    //获取 cipher
    private static Cipher getCipher(byte[] key, int model) throws Exception {
        SecretKeySpec secretKeySpec = new SecretKeySpec(key, "AES");
        Cipher cipher = Cipher.getInstance(AES_ALGORITHM);
        cipher.init(model, secretKeySpec);
        return cipher;
    }

    //AES加密
    public static String encrypt(String data, String key) throws Exception {
        Cipher cipher = getCipher(key.getBytes("UTF-8"), Cipher.ENCRYPT_MODE);
        return Base64.getEncoder().encodeToString(cipher.doFinal(data.getBytes("UTF-8")));
    }

    //AES解密
    public static String decrypt(String data, String key) throws Exception {
        Cipher cipher = getCipher(key.getBytes("UTF-8"), Cipher.DECRYPT_MODE);
        return new String(cipher.doFinal(Base64.getDecoder().decode(data.getBytes("UTF-8"))), "UTF-8");
    }
}
