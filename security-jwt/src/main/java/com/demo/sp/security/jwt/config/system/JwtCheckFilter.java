package com.demo.sp.security.jwt.config.system;

import com.auth0.jwt.interfaces.DecodedJWT;
import com.demo.sp.security.jwt.util.JWTUtilExt;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.lang3.StringUtils;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.OncePerRequestFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

/**
 * JWT登录检测Filter
 **/
@Slf4j
public class JwtCheckFilter extends OncePerRequestFilter {
    
    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {
        String aouth = request.getHeader("aouth");
        log.info("获取请求头：" + aouth);
        
        DecodedJWT decodedJWT = null;
        if(StringUtils.isNotBlank(aouth)){
            decodedJWT = JWTUtilExt.verify(aouth);
        }
        if (decodedJWT == null) {
            // 认证失败
            log.info("认证失败");
            filterChain.doFilter(request, response);
            return;
        }
        
        String userName = JWTUtilExt.getUserName(decodedJWT);
        // TODO 查询密码+校验其他信息
        String password = "123456";
        
        log.info("认证成功");
        JwtLoginToken jwtLoginToken = new JwtLoginToken(userName, password, AuthorityUtils.createAuthorityList("admin", "role"));
        SecurityContextHolder.getContext().setAuthentication(jwtLoginToken);
        filterChain.doFilter(request, response);
    }
}
