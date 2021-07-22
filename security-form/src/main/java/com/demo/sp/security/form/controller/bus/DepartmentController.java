package com.demo.sp.security.form.controller.bus;

import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.servlet.ModelAndView;


@Controller
@RequestMapping("department")
public class DepartmentController {
    
    @PreAuthorize("hasAuthority('department:list')")
    @RequestMapping("list")
    public ModelAndView list() {
        return new ModelAndView("department/department_list");
    }
    
    @PreAuthorize("hasAuthority('department:add')")
    //@PreAuthorize("hasRole('admin')")
    @ResponseBody
    @RequestMapping("add")
    public String add() {
        return "department add ...";
    }
    
    @PreAuthorize("hasAuthority('department:edit')")
    @ResponseBody
    @RequestMapping("edit")
    public String edit() {
        return "department add ...";
    }
    
    @PreAuthorize("@customAccessForDepartmentDelete.hasPermission(#request,#authentication)")// 自定义权限控制
    @ResponseBody
    @RequestMapping("delete")
    public String delete() {
        return "department delete ...";
    }
    
    @PreAuthorize("hasAuthority('department:test')")
    @ResponseBody
    @RequestMapping("test")
    public String test() {
        return "department test ...";
    }
    
}
