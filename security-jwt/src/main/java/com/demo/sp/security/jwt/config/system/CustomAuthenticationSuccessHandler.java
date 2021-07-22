package com.demo.sp.security.jwt.config.system;

import com.demo.sp.security.jwt.base.BaseResponse;
import com.demo.sp.security.jwt.util.JWTUtilExt;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.stereotype.Component;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.io.Writer;

/**
 * 自定义认证成功句柄
 **/
@Component
public class CustomAuthenticationSuccessHandler implements AuthenticationSuccessHandler {
    @Override
    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication) throws IOException, ServletException {
        // TODO 自定义登录成功业务逻辑
    
    
        String token = JWTUtilExt.sign(authentication.getName());
        response.setContentType("application/json;charset=UTF-8");
        Writer writer = response.getWriter();
        writer.write(new BaseResponse<>(true,token,"认证成功").toJson());
        writer.flush();
        writer.close();
    }
}
