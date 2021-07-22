package com.demo.sp.security.jwt.controller;

import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.ResponseBody;

/**
 * 测试API
 **/
@Controller
@RequestMapping("api")
public class ApiControlelr {
    
    @ResponseBody
    @RequestMapping("test")
    public String test(){
        return "api test";
    }
    
}
