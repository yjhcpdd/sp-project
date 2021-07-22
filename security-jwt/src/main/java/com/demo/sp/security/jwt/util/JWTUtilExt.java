package com.demo.sp.security.jwt.util;

import com.auth0.jwt.interfaces.DecodedJWT;

import java.util.HashMap;
import java.util.Map;

/**
 * JWTUtil自定义扩展类
 **/
public class JWTUtilExt {
    
    /**
     * 过期时间(2小时)
     */
    private static final long EXPIRE_TIME = 2 * 60 * 60 * 1000L;
    
    /**
     * token存储“用户名”标识
     */
    private static final String CLAIM_NAME = "name";
    
    /**
     * JWT加密密钥（也可以每个用户加密时，使用自己的密码）
     */
    private static final String SECRET_KEY = "mySecretKey";
    
    /**
     * 认证
     *
     * @param userName 用户名
     * @return 生成token
     */
    public static String sign(String userName) {
        Map<String, String> claimMap = new HashMap<>(1);
        claimMap.put(CLAIM_NAME, userName);
        return JWTUtil.sign(claimMap, SECRET_KEY, EXPIRE_TIME);
    }
    
    /**
     * 验证token
     *
     * @param token token
     * @return 验证失败，返回null；验证成功，返回DecodedJWT对象
     */
    public static DecodedJWT verify(String token) {
        return JWTUtil.verify(token, SECRET_KEY);
    }
    
    /**
     * 获取用户名
     *
     * @param decodedJWT
     * @return
     */
    public static String getUserName(DecodedJWT decodedJWT) {
        return JWTUtil.getClaimValueByJwt(decodedJWT, CLAIM_NAME);
    }
    
    public static void main(String[] args) {
        // 生成token
        String token = JWTUtilExt.sign("张三");
        System.out.println("生成token："+token);
        // 验证token
        DecodedJWT decodedJWT = JWTUtilExt.verify("eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJuYW1lIjoi5byg5LiJIiwiZXhwIjoxNjI1NzI2OTI0fQ.VXCEqwS318OF-3vj2nYcE1dPC6HNFjFUK270lTalFi0");
        if (decodedJWT == null) {
            System.out.println("验证失败");
        } else {
            System.out.println("验证成功：" + JWTUtilExt.getUserName(decodedJWT));
            
        }
        
    }
    
    
}
