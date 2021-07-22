package com.demo.sp.security.jwt.config.system;

import com.demo.sp.security.jwt.base.BaseResponse;
import org.springframework.security.authentication.*;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.stereotype.Component;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.io.Writer;

/**
 * 权限认证失败处理器
 *
 **/
@Component
public class CustomAuthenticationFailureHandler implements AuthenticationFailureHandler {
    
    @Override
    public void onAuthenticationFailure(HttpServletRequest request, HttpServletResponse response, AuthenticationException exception) throws IOException, ServletException {
        // TODO 自定义登录失败业务逻辑
    
        String error;
        if (exception instanceof BadCredentialsException) {
            error = "用户名或者密码输入错误，请重新输入!";
        } else if (exception instanceof LockedException) {
            error = "账户被锁定，请联系管理员!";
        } else if (exception instanceof CredentialsExpiredException) {
            error = "密码过期，请联系管理员!";
        } else if (exception instanceof AccountExpiredException) {
            error = "账户过期，请联系管理员!";
        } else if (exception instanceof DisabledException) {
            error = "账户被禁用，请联系管理员!";
        } else {
            error = "认证失败";
        }
        response.setContentType("application/json;charset=UTF-8");
        Writer writer = response.getWriter();
        writer.write(new BaseResponse<String>(true,null,error).toJson());
        writer.flush();
        writer.close();
    }
}
