package com.demo.sp.security.form;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;


@SpringBootApplication
public class SecurityFormApplication {
    public static void main(String[] args) {
        SpringApplication.run(SecurityFormApplication.class, args);
    }
}
