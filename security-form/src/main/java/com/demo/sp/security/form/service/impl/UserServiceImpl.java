package com.demo.sp.security.form.service.impl;

import com.demo.sp.security.form.model.UserInfo;
import com.demo.sp.security.form.service.UserService;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import javax.annotation.Resource;
import java.util.ArrayList;
import java.util.List;

@Service
public class UserServiceImpl implements UserService {
    
    @Resource
    private PasswordEncoder passwordEncoder;
    
    @Override
    public UserInfo getUserInfoByUserName(String userName) {
        if ("admin".equals(userName)) {
            UserInfo userInfo = new UserInfo();
            userInfo.setUserName("admin");
            userInfo.setDepartmentCode("000");
            userInfo.setPassword(passwordEncoder.encode("123456"));
            return userInfo;
        }
        return null;
    }
    
    @Override
    public List<String> getRoleCodeListByUserName(String userName) {
        List<String> roleCodeList = new ArrayList<>();
        if ("admin".equals(userName)) {
            roleCodeList.add("admin");
        }
        return roleCodeList;
    }
    
    @Override
    public List<String> getPermissionCodeListByUserName(String userName) {
        List<String> permissionCodeList = new ArrayList<>();
        if ("admin".equals(userName)) {
            permissionCodeList.add("user:all");
            permissionCodeList.add("user:list");
            permissionCodeList.add("department:list");
            permissionCodeList.add("department:add");
            permissionCodeList.add("department:test");
        }
        return permissionCodeList;
    }
}
