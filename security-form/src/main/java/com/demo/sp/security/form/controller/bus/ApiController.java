package com.demo.sp.security.form.controller.bus;

import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.ResponseBody;

@Controller
@RequestMapping("api")
public class ApiController {
    
    @ResponseBody
    @RequestMapping("test")
    public String test(){
        return "api test ......";
    }

}
