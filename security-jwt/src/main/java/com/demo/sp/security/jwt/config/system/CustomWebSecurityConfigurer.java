package com.demo.sp.security.jwt.config.system;

import com.demo.sp.security.jwt.base.BaseResponse;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpStatus;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import javax.annotation.Resource;
import java.io.Writer;

/**
 * 自定义WebSecurityConfigurer
 */
@Configuration
public class CustomWebSecurityConfigurer extends WebSecurityConfigurerAdapter {
    
    @Resource
    private UserDetailsService customUserDetailService;
    
    /**
     * 自定义认证成功处理器
     */
    @Resource
    private AuthenticationSuccessHandler customAuthenticationSuccessHandler;
    
    /**
     * 自定义权限认证失败处理器
     */
    @Resource
    private AuthenticationFailureHandler customAuthenticationFailureHandler;
    
    /**
     * 默认密码编码器Bean
     *
     * @return
     */
    @Bean
    public PasswordEncoder passwordEncoder() {
        // 编码器迭代次数10（用以限制密码编码的生成速度）
        return new BCryptPasswordEncoder(10);
    }
    
    @Override
    protected void configure(HttpSecurity http) throws Exception {
        // ---------- [csrf防护] ----------
        // 屏蔽csrf防护
        http.csrf().disable();
        
        // ---------- [表单登录] ----------
        // 禁用表单登录
        http.formLogin().disable();
        
        // ---------- [会话管理] ----------
        // 不创建session（不设置，会自动将jwt用户信息保存到session中）
        http.sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS);
        
        // ---------- [基于表单的身份验证] ----------
        // 顺序很重要，从上而下依次验证
        http.authorizeRequests()
                // 放行“登录”，“退出”等相关权限验证请求
                .antMatchers("/getToken").permitAll()
                // 任意请求需认证通过
                .anyRequest().authenticated();
        
        // ---------- [自定义认证信息] ----------
        http.authenticationProvider(new JwtAuthenticationProvider(customUserDetailService, passwordEncoder()));
        
        // ---------- [拦截器配置] ----------
        // 配置登录拦截器
        http.addFilterAt(new JwtLoginFilter(authenticationManager(),customAuthenticationSuccessHandler,customAuthenticationFailureHandler), UsernamePasswordAuthenticationFilter.class);
        // 配置校验拦截器（在登录拦截器后面）
        http.addFilterAfter(new JwtCheckFilter(), JwtLoginFilter.class);
    
        // ---------- [异常处理]ExceptionTranslationFilter ----------
        http.exceptionHandling()
                // 未通过认证，访问拒绝句柄（未通过认证，无操作权限时）
                .authenticationEntryPoint((request, response, authException) -> {
                    response.setStatus(HttpStatus.FORBIDDEN.value());
                    response.setContentType("application/json;charset=UTF-8");
                    Writer writer = response.getWriter();
                    writer.write(new BaseResponse<String>(true,null,"未通过认证").toJson());
                    writer.flush();
                    writer.close();
                })
                // 通过认证，访问拒绝句柄（认证通过后，无操作权限时）
                .accessDeniedHandler((request, response, accessDeniedException) -> {
                    response.setStatus(HttpStatus.FORBIDDEN.value());
                    response.setContentType("application/json;charset=UTF-8");
                    Writer writer = response.getWriter();
                    writer.write(new BaseResponse<String>(true,null,"无操作权限").toJson());
                    writer.flush();
                    writer.close();
                });
        
    }
    
}
