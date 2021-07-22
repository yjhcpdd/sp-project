package com.demo.sp.security.form.controller.bus;

import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.ResponseBody;

/**
 * 无权限测试
 */
@Controller
@RequestMapping("noPower")
public class NoPowerController {
    
    @ResponseBody
    @RequestMapping("test")
    public String test() {
        return "no power test ......";
    }
    
}
