package com.demo.sp.security.form.controller.system;

import com.demo.sp.security.form.config.system.LoginUser;
import com.demo.sp.security.form.config.system.SecurityUtils;
import org.apache.commons.lang3.StringUtils;
import org.springframework.security.authentication.*;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.web.WebAttributes;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.servlet.ModelAndView;

import javax.servlet.http.HttpServletRequest;

@RequestMapping("/")
@Controller
public class SystemController {
    
    /**
     * 加载登录页面
     *
     * @return
     */
    @RequestMapping(value = {"initLogin"})
    public ModelAndView initLogin(HttpServletRequest request) {
        ModelAndView modelAndView = new ModelAndView("system/login");
        return modelAndView;
    }
    
    /**
     * 登录失败页面
     *
     * @param request
     * @return
     */
    @RequestMapping(value = {"loginFail"})
    public ModelAndView loginFail(HttpServletRequest request) {
        ModelAndView modelAndView = new ModelAndView("system/login");
        String error = null;
        // 登录异常处理
        Object exception = request.getAttribute(WebAttributes.AUTHENTICATION_EXCEPTION);
        if (exception instanceof AuthenticationException) {
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
        }
        modelAndView.addObject("error", error);
        return modelAndView;
    }
    
    /**
     * 加载主页面
     *
     * @return
     */
    @RequestMapping(value = {"/"})
    public ModelAndView main() {
        ModelAndView modelAndView = new ModelAndView("system/main");
        
        // 获取当前登录人信息
        LoginUser loginUser = SecurityUtils.getLoginUser();
        modelAndView.addObject("loginUser", loginUser);
        
        return modelAndView;
    }
    
    /**
     * 无访问权限页面
     *
     * @return
     */
    @RequestMapping("accessDenied")
    public ModelAndView accessDenied() {
        return new ModelAndView("system/accessDenied");
    }
    
}
