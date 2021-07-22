package com.demo.sp.security.jwt.config.system;

import org.apache.commons.lang3.StringUtils;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;

/**
 * 自定义用户查询策略
 **/
@Component
public class CustomUserDetailService implements UserDetailsService {
    
    @Autowired
    private PasswordEncoder passwordEncoder;
    
    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        if(StringUtils.isBlank(username)){
            throw new UsernameNotFoundException("用户名为空");
        }
        if(!"admin".equals(username)){
            throw new UsernameNotFoundException("用户名、密码不正确");
        }
        return new User("admin",passwordEncoder.encode("123456"), AuthorityUtils.createAuthorityList("ROLE_admin","user:add"));
    }
}
