package com.demo.sp.security.form.config.system;

import com.demo.sp.security.form.model.UserInfo;
import com.demo.sp.security.form.service.UserService;
import org.apache.commons.collections4.CollectionUtils;
import org.apache.commons.lang3.StringUtils;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Component;

import javax.annotation.Resource;
import java.util.ArrayList;
import java.util.List;

/**
 * 自定义用户认证service
 */
@Component
public class CustomUserDetailsService implements UserDetailsService {
    
    @Resource
    private UserService userService;
    
    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        // ========== 【1】校验参数 ========== 
        if (StringUtils.isBlank(username)) {
            throw new UsernameNotFoundException("用户代码为空");
        }
        
        // ========== 【2】查询用户信息 ========== 
        UserInfo userInfo = userService.getUserInfoByUserName(username);
        if (userInfo == null) {
            throw new UsernameNotFoundException("用户名或密码错误");
        }
        // 密码
        String password = userInfo.getPassword();
        // 用户其他信息（用户部门代码）
        String departmentCode = userInfo.getDepartmentCode();
        
        // ========== 【3】查询授权信息 ========== 
        // 角色代码和授权代码，均在此列表中配置（角色代码前加“ROLE_”，来和权限区分）
        List<String> authorityList = new ArrayList<>();
        // 初始化角色信息
        List<String> roleCodeList = userService.getRoleCodeListByUserName(username);
        if (CollectionUtils.isNotEmpty(roleCodeList)) {
            for (String roleCode : roleCodeList) {
                authorityList.add("ROLE_" + roleCode);
            }
        }
        // 初始化权限信息
        List<String> permissionCodeList = userService.getPermissionCodeListByUserName(username);
        if (CollectionUtils.isNotEmpty(permissionCodeList)) {
            authorityList.addAll(permissionCodeList);
        }
        
        // ========== 【4】组装用户信息 ==========
        // 组装通用信息
        LoginUser loginUser = new LoginUser(username, password, AuthorityUtils.createAuthorityList(authorityList.toArray(new String[0])));
        // 组装自定义用户信息
        loginUser.setDepartmentCode(departmentCode);
        
        return loginUser;
    }
}
