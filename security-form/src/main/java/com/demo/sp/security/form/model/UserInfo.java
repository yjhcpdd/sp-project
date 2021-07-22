package com.demo.sp.security.form.model;

import lombok.Data;

/**
 * 系统用户实体类
 */
@Data
public class UserInfo {
    
    /**
     * 用户名
     */
    private String userName;
    
    /**
     * 密码
     */
    private String password;
    
    /**
     * 部门代码
     */
    private String departmentCode;
}
