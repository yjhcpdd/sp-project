package com.demo.sp.security.jwt.base;

import com.alibaba.fastjson.JSON;
import com.alibaba.fastjson.serializer.SerializerFeature;
import lombok.Data;

import java.io.Serializable;

/**
 * 基础返回类
 **/
@Data
public class BaseResponse<T> implements Serializable {
    
    /**
     * 成功标志
     */
    private Boolean success;
    
    /**
     * 消息
     */
    private String message;
    
    /**
     * 结果
     */
    private T result;
    
    /**
     * 结果状态码
     */
    private String code;
    
    
    public BaseResponse(Boolean success, T result, String message) {
        this.success = success;
        this.result = result;
        this.message = message;
    }
    
    /**
     * 转换为JSON字符串
     *
     * @return
     */
    public String toJson() {
        return JSON.toJSONString(this, SerializerFeature.WriteMapNullValue);
    }
    
}
