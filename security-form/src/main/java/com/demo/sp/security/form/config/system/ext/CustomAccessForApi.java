package com.demo.sp.security.form.config.system.ext;

import org.apache.commons.lang3.StringUtils;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Component;

import javax.servlet.http.HttpServletRequest;

/**
 * 自定义权限监测
 */
@Component
public class CustomAccessForApi {
    
    /**
     * 权限监测
     *
     * @param authentication
     * @return
     */
    public boolean hasPermission(HttpServletRequest request, Authentication authentication) {
        if (StringUtils.startsWith(request.getRemoteAddr(), "192.168.56")) {
            // 满足条件的IP，可以访问此接口
            return true;
        }
        return false;
    }
    
}
