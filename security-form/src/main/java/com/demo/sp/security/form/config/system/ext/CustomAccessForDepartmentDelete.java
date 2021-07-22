package com.demo.sp.security.form.config.system.ext;

import org.springframework.context.annotation.Configuration;
import org.springframework.security.core.Authentication;

import javax.servlet.http.HttpServletRequest;

/**
 * 自定义权限控制
 */
@Configuration
public class CustomAccessForDepartmentDelete {
    public boolean hasPermission(HttpServletRequest request, Authentication authentication) {
        return false;
    }
}
