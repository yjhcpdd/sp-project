package com.demo.sp.security.jwt.config.system;

import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.password.PasswordEncoder;

/**
 * JWT权限验证器
 */
public class JwtAuthenticationProvider extends DaoAuthenticationProvider {
    
    /**
     * 构造函数
     * @param userDetailsService
     * @param passwordEncoder
     */
    public JwtAuthenticationProvider(UserDetailsService userDetailsService, PasswordEncoder passwordEncoder) {
        super.setUserDetailsService(userDetailsService);
        super.setPasswordEncoder(passwordEncoder);
    }
    
    /**
     * 支持自定义token类
     *
     * @param authentication
     * @return
     */
    @Override
    public boolean supports(Class<?> authentication) {
        // 支持对JwtLoginToken的验证
        return (JwtLoginToken.class.isAssignableFrom(authentication));
    }
    
    @Override
    protected Authentication createSuccessAuthentication(Object principal, Authentication authentication, UserDetails user) {
        // 返回验证成功对象
        JwtLoginToken result = new JwtLoginToken(principal, authentication.getCredentials(), user.getAuthorities());
        result.setDetails(authentication.getDetails());
        return result;
    }
    
}
