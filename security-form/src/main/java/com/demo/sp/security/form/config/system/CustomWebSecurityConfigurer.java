package com.demo.sp.security.form.config.system;

import com.alibaba.fastjson.JSONObject;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpStatus;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

import java.io.Writer;

/**
 * 自定义WebSecurityConfigurer
 */
@Configuration
// 开启全局“方法安全”控制(开启方法前后权限判断，一般使用@PreAuthorize进行方法执行前判断)
@EnableGlobalMethodSecurity(prePostEnabled = true)
public class CustomWebSecurityConfigurer extends WebSecurityConfigurerAdapter {
    
    /**
     * 自定义登录成功逻辑
     */
    @Autowired
    private CustomLoginSuccessHandler customLoginSuccessHandler;
    
    /**
     * 自定义登出成功逻辑
     */
    @Autowired
    private CustomLogoutSuccessHandler customLogoutSuccessHandler;
    
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
    public void configure(WebSecurity web) throws Exception {
        // ---------- [忽略资源请求] ----------
        // 不经过security过滤器（一般为静态资源）
        web.ignoring().antMatchers("/css/**", "/js/**");
    }
    
    @Override
    protected void configure(HttpSecurity http) throws Exception {
        // ---------- [csrf防护] ----------
        // 屏蔽csrf防护
        http.csrf().disable();
        
        // ---------- [基于表单的身份验证] ----------
        // 顺序很重要，从上而下依次验证
        http.authorizeRequests()
                // ---------- 自定义基于URL授权验证[也可加http方式限制：(HttpMethod method, String... antPatterns)]
                // 判断是否有某权限
                .antMatchers("/noPower/**").hasAuthority("noPower")
                // 判断是否有某角色
                .antMatchers("/admin/**").hasRole("admin")
                // 判断是否有任一权限
                .antMatchers("/user/list").hasAnyAuthority("user:list", "user:all")
                // 自定义权限校验（参数来自WebSecurityExpressionRoot属性）
                .antMatchers("/api/**").access("@customAccessForApi.hasPermission(request,authentication)")
                // 放行“登录”，“退出”等相关权限验证请求
                .antMatchers("/initLogin", "/doLogin", "/doLogout").permitAll()
                // 任意请求需认证通过
                .anyRequest().authenticated();
        
        // ---------- [表单登录] ----------
        http.formLogin()
                // 登录时自定义“用户”参数名（默认为：username）
                .usernameParameter("username")
                // 登录时自定义“用户”参数名（默认为：password）
                .passwordParameter("password")
                // 自定义登录页面（默认为：login/GET）
                .loginPage("/initLogin")
                // 自定义登录请求路径（默认为：login/POST)
                .loginProcessingUrl("/doLogin")
                // 自定义登录成功forward路径
                //.successForwardUrl("/")
                // 自定义登录成功redirect路径【默认】(登录成功后，页面重定向到跳转登录页面前的页面Referer)
                //.defaultSuccessUrl("/")
                // 自定义登录成功逻辑（redirect主页面+自定义业务逻辑）
                .successHandler(customLoginSuccessHandler)
                // 自定义登录成功redirect路径(登录成功后，页面重定向到设置的登录成功页面:"/")
                //.defaultSuccessUrl("/", true)
                // 自定义失败forward路径（默认为：loginPage + "?error"）
                .failureForwardUrl("/loginFail")
        ;
        
        // ---------- [登出系统] ----------
        http.logout()
                // 删除认证信息（默认为true）
                .clearAuthentication(true)
                // 退出系统时使session无效（默认为true）
                .invalidateHttpSession(true)
                // 退出系统时，自定义请求路径
                .logoutUrl("/doLogout")
                // 自定义登出成功逻辑（redirect登录页面+自定义业务逻辑）
                .logoutSuccessHandler(customLogoutSuccessHandler);
        
        // ---------- [异常处理]ExceptionTranslationFilter ----------
        http.exceptionHandling()
                // // 未通过认证，访问拒绝句柄（未通过认证，无操作权限时）（不使用默认的表单form登录认证时，可使用此方式）
                //.authenticationEntryPoint((request, response, authException) -> {
                //})
                // 访问拒绝句柄（认证通过后，无操作权限时）
                .accessDeniedHandler((request, response, accessDeniedException) -> {
                    String contentType = request.getHeader("content-type");
                    boolean jsonRequestFlag = (contentType != null && contentType.contains("json"));
                    // 判断是否是json请求
                    if (jsonRequestFlag) {
                        response.setStatus(HttpStatus.FORBIDDEN.value());
                        response.setContentType("application/json;charset=UTF-8");
                        Writer writer = response.getWriter();
                        JSONObject json = new JSONObject();
                        json.put("success", false);
                        json.put("message", "无操作权限：" + accessDeniedException.getMessage());
                        writer.write(json.toJSONString());
                        writer.flush();
                        writer.close();
                    } else {
                        request.getRequestDispatcher("/accessDenied").forward(request, response);
                    }
                });
        
        // ---------- [会话管理] ----------
        http.sessionManagement()
                // session创建机制，默认为IF_REQUIRED（只在需要时创建）
                .sessionCreationPolicy(SessionCreationPolicy.IF_REQUIRED);
    }
    
}
