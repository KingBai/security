package com.lighting.security.controller;


import org.springframework.stereotype.Controller;
import org.springframework.ui.ModelMap;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.ResponseBody;

/**
 * @date：2018年9月19日 上午11:43:26
 * @author liyuhao
 * @version 1.0
 * @since JDK 1.8
 * @description：
 */
@Controller
public class HelloController {

    @RequestMapping("/hello")
    @ResponseBody
    public String toTest() {
        return "Hello World";
    }

    // 登录
    @PostMapping("/login")
    public String index(String username,String password) {
        return "index";
    }

    // 登录成功之后的首页
    @GetMapping("/index")
    public String index() {
        return "index";
    }

    // 日志管理
    @GetMapping("/syslog")
    public String showOrder() {
        return "syslog";
    }

    // 用户管理
    @GetMapping("/sysuser")
    public String addOrder() {
        return "sysuser";
    }

    // 具体业务一
    @GetMapping("/biz1")
    public String updateOrder() {
        return "biz1";
    }

    // 具体业务二
    @GetMapping("/biz2")
    public String deleteOrder() {
        return "biz2";
    }

}