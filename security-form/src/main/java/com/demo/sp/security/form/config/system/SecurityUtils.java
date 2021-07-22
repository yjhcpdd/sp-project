package com.demo.sp.security.form.config.system;

import org.apache.commons.collections4.CollectionUtils;
import org.apache.commons.lang3.StringUtils;
import org.springframework.beans.BeansException;
import org.springframework.context.ApplicationContext;
import org.springframework.context.ApplicationContextAware;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;

import java.util.Collection;
import java.util.HashSet;
import java.util.Set;

/**
 * security工具类
 */
public class SecurityUtils {
    
    /**
     * 默认角色前缀
     */
    private static final String DEFAULT_ROLE_PREFIX = "ROLE_";
    
    /**
     * 获取认证信息
     *
     * @return
     */
    public static Authentication getAuthentication() {
        SecurityContext securityContext = SecurityContextHolder.getContext();
        if (securityContext != null) {
            return securityContext.getAuthentication();
        }
        return null;
    }
    
    /**
     * 获取当前登录用户对象
     *
     * @return
     */
    public static LoginUser getLoginUser() {
        Authentication authentication = SecurityUtils.getAuthentication();
        if (authentication != null) {
            return (LoginUser) authentication.getPrincipal();
        }
        return null;
    }
    
    /**
     * 判断有某权限（暂不支持权限继承）
     *
     * @return
     */
    public static boolean hasAuthority(String authority) {
        if (StringUtils.isNotEmpty(authority)) {
            return SecurityUtils.hasAnyAuthorityName(null, authority);
        }
        return false;
    }
    
    /**
     * 判断有任一权限（暂不支持权限继承）
     *
     * @param authorityArr
     * @return
     */
    public static boolean hasAnyAuthority(String... authorityArr) {
        if (authorityArr != null && authorityArr.length > 0) {
            return SecurityUtils.hasAnyAuthorityName(null, authorityArr);
        }
        return false;
    }
    
    /**
     * 判断有某角色（暂不支持权限继承）
     *
     * @param role
     * @return
     */
    public static boolean hasRole(String role) {
        if (StringUtils.isNotEmpty(role)) {
            return SecurityUtils.hasAnyAuthorityName(DEFAULT_ROLE_PREFIX, role);
        }
        return false;
    }
    
    /**
     * 判断有任一角色（暂不支持权限继承）
     *
     * @param roleArr
     * @return
     */
    public static boolean hasAnyRole(String... roleArr) {
        if (roleArr != null && roleArr.length > 0) {
            return SecurityUtils.hasAnyAuthorityName(DEFAULT_ROLE_PREFIX, roleArr);
        }
        return false;
    }
    
    /**
     * 判断是否满足通用权限信息，有一个满足即为满足（包括角色和权限）
     *
     * @param prefix         前缀
     * @param authorityNames 权限名称
     * @return
     */
    private static boolean hasAnyAuthorityName(String prefix, String... authorityNames) {
        if (authorityNames != null && authorityNames.length > 0) {
            Set<String> authoritySet = SecurityUtils.getAuthoritySet();
            if (CollectionUtils.isNotEmpty(authoritySet)) {
                for (String authorityName : authorityNames) {
                    String defaultedRole = getRoleWithDefaultPrefix(prefix, authorityName);
                    if (authoritySet.contains(defaultedRole)) {
                        return true;
                    }
                }
            }
        }
        return false;
    }
    
    /**
     * 获取当前用户权限集合信息
     *
     * @return
     */
    private static Set<String> getAuthoritySet() {
        Authentication authentication = SecurityUtils.getAuthentication();
        if (authentication != null) {
            Collection<? extends GrantedAuthority> userAuthorities = authentication.getAuthorities();
            return AuthorityUtils.authorityListToSet(userAuthorities);
        }
        return null;
    }
    
    /**
     * 如果defaultRolePrefix为非空且role的开头不是defaultRolePrefix，则使用defaultRolePrefix前缀角色。
     *
     * @param defaultRolePrefix
     * @param role
     * @return
     */
    private static String getRoleWithDefaultPrefix(String defaultRolePrefix, String role) {
        if (role == null) {
            return role;
        }
        if (defaultRolePrefix == null || defaultRolePrefix.length() == 0) {
            return role;
        }
        if (role.startsWith(defaultRolePrefix)) {
            return role;
        }
        return defaultRolePrefix + role;
    }
}
