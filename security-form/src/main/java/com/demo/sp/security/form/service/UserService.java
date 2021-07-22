package com.demo.sp.security.form.service;

import com.demo.sp.security.form.model.UserInfo;

import java.util.List;

/**
 * 用户service
 */
public interface UserService {
    
    /**
     * 根据用户名称查询用户信息
     *
     * @param userName 用户名
     * @return
     */
    UserInfo getUserInfoByUserName(String userName);
    
    /**
     * 根据用户名，查询角色代码列表
     *
     * @param userName 用户名
     * @return
     */
    List<String> getRoleCodeListByUserName(String userName);
    
    /**
     * 根据用户名，查询权限代码列表
     *
     * @param userName 用户名
     * @return
     */
    List<String> getPermissionCodeListByUserName(String userName);
    
}
