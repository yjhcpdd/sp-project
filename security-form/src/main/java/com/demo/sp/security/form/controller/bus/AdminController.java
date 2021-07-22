package com.demo.sp.security.form.controller.bus;

import com.demo.sp.security.form.config.system.SecurityUtils;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.ResponseBody;

@Controller
@RequestMapping("admin")
public class AdminController {

    @ResponseBody
    @RequestMapping("test")
    public String test(){
        return "admin test ......";
    }
    
    @ResponseBody
    @RequestMapping("apiPower")
    public String apiPower(){
        StringBuilder result = new StringBuilder();
        result.append("判断有角色（admin）：").append(SecurityUtils.hasAnyRole("admin")).append("<br>");
        result.append("判断有权限（user:list）：").append(SecurityUtils.hasAuthority("user:list")).append("<br>");
        result.append("判断有权限（user:noPower）：").append(SecurityUtils.hasAuthority("user:noPower")).append("<br>");
        
        return result.toString();
    }
    
}
