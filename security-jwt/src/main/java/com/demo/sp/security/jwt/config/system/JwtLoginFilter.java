package com.demo.sp.security.jwt.config.system;

import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

/**
 * JWT登录拦截器
 */
public class JwtLoginFilter extends UsernamePasswordAuthenticationFilter {
    
    public JwtLoginFilter(AuthenticationManager authenticationManager, AuthenticationSuccessHandler authenticationSuccessHandler, AuthenticationFailureHandler authenticationFailureHandler) {
        // 设置匹配的请求路径
        super.setRequiresAuthenticationRequestMatcher(new AntPathRequestMatcher("/getToken"));
        super.setAuthenticationManager(authenticationManager);
        super.setAuthenticationSuccessHandler(authenticationSuccessHandler);
        super.setAuthenticationFailureHandler(authenticationFailureHandler);
    }
    
    @Override
    public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response) throws AuthenticationException {
        String username = super.obtainUsername(request);
        String password = super.obtainPassword(request);
        
        if (username == null) {
            username = "";
        }
        
        if (password == null) {
            password = "";
        }
        
        username = username.trim();
        
        // 创建未认证的凭证
        JwtLoginToken authRequest = new JwtLoginToken(username, password);
        
        // Allow subclasses to set the "details" property
        super.setDetails(request, authRequest);
        
        // 委托JwtAuthenticationProvider进行认证处理
        return this.getAuthenticationManager().authenticate(authRequest);
    }

}
