## springSecurity非前后端分离配置（生产环境可用）

### 1 场景

#### 1.1 说明

springSecurity作为一个权限管理系统，在生产环境使用，还是比较复杂的，涉及的相关点比较多。网上文章里，并没有比较全的配置。

本文主要将springSecurity在生产环境中使用时，需要注意到的地方，进行了相关整理。

springSecurity默认是`基于session的非前后端分离`场景，本文基于此场景进行配置，有时间的时候，后续会记录补充如下场景：
（1）非前后端分离
（2）基于JWT的非前后端分离
（3）网关上整合权限控制

#### 1.2 源码

**本文是基于各个应用模块单独写的配置，完整的测试代码，可关注、点赞后私信博主。所有的代码，博主均已校验过，demo可正常跑通，可直接应用到生产环境中。**

#### 1.3 版本

**spring-boot版本：**2.3.3.RELEASE

其他版本：

```xml
<!-- ==========【freemarker权限security标签支持】========== start -->
<dependency>
    <groupId>org.springframework.security</groupId>
    <artifactId>spring-security-taglibs</artifactId>
    <version>5.3.4.RELEASE</version>
</dependency>
<dependency>
    <groupId>javax.servlet.jsp</groupId>
    <artifactId>javax.servlet.jsp-api</artifactId>
    <version>2.3.3</version>
    <scope>provided</scope>
</dependency>
<!-- ==========【freemarker权限security标签支持】========== end -->
```

### 2 登录

前提，屏蔽csrf防护，否则系统登录、登出无法正常访问。如需打开，需自己进行相关配置。

```java
// 屏蔽csrf防护
http.csrf().disable();
```

#### 2.1 自定义登录页面

本文前端页面，使用的`freemarker`。

##### 2.1.1 页面配置

springSecurity登录表单默认使用的是自己的页面，一般系统都需要进行`自定义登录页面`。

访问系统页面时，如`未认证`，则`自动跳转到登录页面`。

文件路径：resources\templates\system\main.ftlh

如下：

```html
<form action="/doLogin" method="post">
    <table>
        <tr>
            <td>用户名：</td>
            <td><input type="text" name="username" value="admin"></td>
        </tr>
        <tr>
            <td>密码：</td>
            <td><input type="text" name="password" value="123456"></td>
        </tr>
        <tr>
            <td><input type="submit" value="登录"></td>
        </tr>
    </table>
</form>
```

如上代码所示，登录时的相关参数如下：

| 参数描述         | 参数       |
| ---------------- | ---------- |
| 加载登录页面路径 | /initLogin |
| 提交登录请求路径 | /doLogin   |
| 用户名           | username   |
| 密码             | password   |

##### 2.1.2 后台代码配置

```java
/**
  * 加载登录页面
  * @return
  */
@RequestMapping(value = {"initLogin"})
public ModelAndView initLogin(HttpServletRequest request) {
    ModelAndView modelAndView = new ModelAndView("system/login");
    return modelAndView;
}
```

**备注：**`提交登录请求路径（/doLogin）`无需配置，此请求，会走security自己的认证流程。

##### 2.1.3 登录请求放行

放行“登录页面”，“登录请求”等相关权限验证请求

```java
http.authorizeRequests()
    // ......
    // 放行“登录页面”，“登录请求”，“退出”等相关权限验证请求
    .antMatchers("/initLogin", "/doLogin", "/doLogout").permitAll()
    // 任意请求需认证通过
    .anyRequest().authenticated();
```

##### 2.1.4 登录参数配置

security的登录请求路径和参数都是默认配置的，这里我们更改为自己的请求配置：

```java
http.formLogin()
    // 登录时自定义“用户”参数名（默认为：username）
    .usernameParameter("username")
    // 登录时自定义“用户”参数名（默认为：password）
    .passwordParameter("password")
    // 自定义登录页面（默认为：login/GET）
    .loginPage("/initLogin")
    // 自定义登录请求路径（默认为：login/POST)
    .loginProcessingUrl("/doLogin")
```

#### 2.2 登录校验逻辑

##### 2.1 自定义登录用户对象

扩展security自带的用户对象（org.springframework.security.core.userdetails.User），扩展自定义属性

```java
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.User;
import java.util.Collection;

/**
 * 自定义用户对象
 */
public class LoginUser extends User {
    
    /**
     * 自定义用户属性
     */
    private String departmentCode;
    
    public LoginUser(String username, String password, Collection<? extends GrantedAuthority> authorities) {
        super(username, password, authorities);
    }
    
    public String getDepartmentCode() {
        return departmentCode;
    }
    
    public void setDepartmentCode(String departmentCode) {
        this.departmentCode = departmentCode;
    }
}
```

##### 2.2 自定义用户认证service

自定义用户认证，主要是将用户根据用户名，从数据库中查询出来。组装好org.springframework.security.core.userdetails.`UserDetails`的实现类对象，交由security进行验证。后续security的验证，如未抛出异常，则认证通过，否则认证失败，然后，可根据抛出的异常类型，来识别认证失败的原因。

```java
/**
 * 自定义用户认证service
 */
@Component
public class CustomUserDetailsService implements UserDetailsService {
    
    @Resource
    private UserService userService;
    
    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        // ========== 【1】校验参数 ========== 
        if (StringUtils.isBlank(username)) {
            throw new UsernameNotFoundException("用户代码为空");
        }
        
        // ========== 【2】查询用户信息 ========== 
        UserInfo userInfo = userService.getUserInfoByUserName(username);
        if (userInfo == null) {
            throw new UsernameNotFoundException("用户名或密码错误");
        }
        // 密码
        String password = userInfo.getPassword();
        // 用户其他信息（用户部门代码）
        String departmentCode = userInfo.getDepartmentCode();
        
        // ========== 【3】查询授权信息 ========== 
        // 角色代码和授权代码，均在此列表中配置（角色代码前加“ROLE_”，来和权限区分）
        List<String> authorityList = new ArrayList<>();
        // 初始化角色信息
        List<String> roleCodeList = userService.getRoleCodeListByUserName(username);
        if (CollectionUtils.isNotEmpty(roleCodeList)) {
            for (String roleCode : roleCodeList) {
                authorityList.add("ROLE_" + roleCode);
            }
        }
        // 初始化权限信息
        List<String> permissionCodeList = userService.getPermissionCodeListByUserName(username);
        if (CollectionUtils.isNotEmpty(permissionCodeList)) {
            authorityList.addAll(permissionCodeList);
        }
        
        // ========== 【4】组装用户信息 ==========
        // 组装通用信息
        LoginUser loginUser = new LoginUser(username, password, AuthorityUtils.createAuthorityList(authorityList.toArray(new String[0])));
        // 组装自定义用户信息
        loginUser.setDepartmentCode(departmentCode);
        
        return loginUser;
    }
}
```

#### 2.3 认证通过逻辑

认证通过后，需进行页面跳转，有两种方式，一种是跳转到访问登录页面前的页面（访问某个页面，因为未认证，自动跳转到登录页面，当登录成功后，自动跳转到此页面，而不是系统主页面），一种是跳转到系统主页面。

可根据实际业务需求选择，这里选择第一种。

一般登录成功后，系统会执行自定义逻辑，如记录登录IP、登录时间等，这里使用`自定义登录成功逻辑`。

##### 2.3.1 自定义登录成功处理器

```java
/**
 * 自定义登录成功处理器
 */
@Component
public class CustomLoginSuccessHandler extends SavedRequestAwareAuthenticationSuccessHandler {
    
    @Override
    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication) throws ServletException, IOException {
        // TODO 自定义登录成功逻辑......
        System.out.println("自定义登录成功逻辑......");
        super.onAuthenticationSuccess(request, response, authentication);
    }
}
```

##### 2.3.2 配置登录成功逻辑

- **注入bean**

```java
/**
  * 自定义登录成功逻辑
 */
@Autowired
private CustomLoginSuccessHandler customLoginSuccessHandler;
```

- **配置执行器**

```java
http.formLogin()
    // 自定义登录成功forward路径
    //.successForwardUrl("/")
    // 自定义登录成功redirect路径【默认】(登录成功后，页面重定向到跳转登录页面前的页面Referer)
    //.defaultSuccessUrl("/")
    // 自定义登录成功逻辑（redirect主页面+自定义业务逻辑）
    .successHandler(customLoginSuccessHandler)
    // 自定义登录成功redirect路径(登录成功后，页面重定向到设置的登录成功页面:"/")
	//.defaultSuccessUrl("/", true)
```

##### 2.3.3 登录主页面后台代码

```java
/**
  * 系统主页面
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
```

#### 2.4 获取认证信息

security认证通过后，会将认证信息，保存在ThreadLocal中，故可以通过其自带的静态方法获取：

**SecurityContextHolder.getContext().getAuthentication()**

此处可获取2.2中封装的自定义对象：LoginUser。

```java
/**
 * security工具类
 */
public class SecurityUtils {
    
    /**
     * 默认角色前缀
     */
    private static final String DEFAULT_ROLE_PREFIX = "ROLE_";
    
    /**
     * 获取认证信息
     * @return
     */
    public static Authentication getAuthentication() {
        SecurityContext securityContext = SecurityContextHolder.getContext();
        if (securityContext != null) {
            return securityContext.getAuthentication();
        }
        return null;
    }
    
    /**
     * 获取当前登录用户对象
     * @return
     */
    public static LoginUser getLoginUser() {
        Authentication authentication = SecurityUtils.getAuthentication();
        if (authentication != null) {
            return (LoginUser) authentication.getPrincipal();
        }
        return null;
    }
}
```

#### 2.5 认证失败逻辑

认证失败时，跳转到登录页面，并返回错误信息。

这里我们通过forward到认证失败页面（即登录页面），由于使用的是forward进行的跳转，故可以获取request中的属性`WebAttributes.AUTHENTICATION_EXCEPTION`，来获取异常信息，来返回到前台。

> 也可通过redirect到认证失败页面（登录页面），但是请求中无法获取失败异常信息WebAttributes.AUTHENTICATION_EXCEPTION。
> 可以考虑自定义认证失败逻辑`failureHandler`，来实现此功能。

##### 2.5.1 认证失败后台

```java
/**
  * 登录失败页面
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
        if(exception instanceof UsernameNotFoundException){
            // 自己抛出异常信息
            error = ((UsernameNotFoundException) exception).getMessage();
        }else if (exception instanceof BadCredentialsException){
            error = "用户名或者密码输入错误，请重新输入!";
        }else if (exception instanceof LockedException){
            error = "账户被锁定，请联系管理员!";
        }else if (exception instanceof CredentialsExpiredException){
            error = "密码过期，请联系管理员!";
        }else if (exception instanceof AccountExpiredException){
            error = "账户过期，请联系管理员!";
        }else if (exception instanceof DisabledException){
            error = "账户被禁用，请联系管理员!";
        }else{
            error = "认证失败";
        }
    }
    modelAndView.addObject("error", error);
    return modelAndView;
}
```

##### 2.5.2 认证失败配置

```java
http.formLogin()
    // 自定义失败forward路径（默认为：loginPage + "?error"）
    .failureForwardUrl("/loginFail")
```

### 2 登出

#### 2.1 页面配置

```html
<a href="/doLogout">退出</a>
```

#### 2.2 后台代码

登出，走的是security的逻辑，无需自己写后台代码。

#### 2.3 登出请求放行

有可能执行登出操作的时候，session已失效，因此登出系统也需要放行请求，不进行认证校验

```java
http.authorizeRequests()
    // ......
    // 放行“登录页面”，“登录请求”，“退出”等相关权限验证请求
    .antMatchers("/initLogin", "/doLogin", "/doLogout").permitAll()
    // 任意请求需认证通过
    .anyRequest().authenticated();
```

#### 2.4 自定义登出处理器

一般系统登出时，也会进行相关业务操作，如记录日志，发送消息等。

##### 2.4.1 自定义登出成功处理器

```java
/**
 * 自定义登出成功处理器
 **/
@Configuration
public class CustomLogoutSuccessHandler extends SimpleUrlLogoutSuccessHandler {
    @Override
    public void onLogoutSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication) throws IOException, ServletException {
        // TODO 自定义登出成功逻辑......
        System.out.println("自定义登出成功逻辑......");
        super.onLogoutSuccess(request, response, authentication);
    }
}
```

##### 2.4.2 配置登录成功逻辑

- **注入bean**

```java
/**
  * 自定义登出成功逻辑
  */
@Autowired
private CustomLogoutSuccessHandler customLogoutSuccessHandler;
```

- **配置执行器**

```java
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
```

### 3 URL授权验证

security可以对指定URL进行授权验证判断。个人认为主要是用来对某些`特殊访问请求进行专门的认证`（如api），`一般不会在此配置角色权限的验证`。

##### 3.1 验证配置

```java
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
```

认证通过对请求进行拦截，如`antMatchers`，可以使用多种认证方式：

- 使用`hasRole`对角色进行认证
- 可以使用`hasAuthority`对权限认证。

- 通过`自定义逻辑`对请求进行进行认证

#### 3.2 自定义逻辑验证

##### 3.2.1 自定义验证逻辑

```java
/**
 * 自定义权限监测
 */
@Component
public class CustomAccessForApi {
    /**
     * 权限监测
     */
    public boolean hasPermission(HttpServletRequest request, Authentication authentication) {
        if (StringUtils.startsWith(request.getRemoteAddr(), "192.168.56")) {
            // 满足条件的IP，可以访问此接口
            return true;
        }
        return false;
    }
}
```

##### 3.2.2 配置自定义验证逻辑

```java
 http.authorizeRequests()
     // 自定义权限校验（参数来自WebSecurityExpressionRoot属性）
     .antMatchers("/api/**").access("@customAccessForApi.hasPermission(request,authentication)")
```

### 4 方法授权验证

security可以对具体某个方法进行授权验证判断，一般加在Controller的对外请求方法上。

此方法，需要配置注解`@EnableGlobalMethodSecurity`开启方法前后权限判断，一般使用`@PreAuthorize`进行方法执行前判断

```java
// 开启全局“方法安全”控制(开启方法前后权限判断，一般使用@PreAuthorize进行方法执行前判断)
@EnableGlobalMethodSecurity(prePostEnabled = true)
```

#### 4.1 判断是否有角色

```java
@PreAuthorize("hasRole('admin')")
@ResponseBody
@RequestMapping("add")
public String add() {
    return "department add ...";
}
```

#### 4.2 判断是否有权限

```java
@PreAuthorize("hasAuthority('department:list')")
@RequestMapping("list")
public ModelAndView list() {
    return new ModelAndView("department/department_list");
}
```

#### 4.3 自定义权限判断

##### 4.3.1 自定义校验器

```java
@Configuration
public class CustomAccessForDepartmentDelete {
    public boolean hasPermission(HttpServletRequest request, Authentication authentication) {
        return false;
    }
}
```

##### 4.3.2 配置自定义校验器

```java
// 自定义权限控制，参数前需加#
@PreAuthorize("@customAccessForDepartmentDelete.hasPermission(#request,#authentication)")
@ResponseBody
@RequestMapping("delete")
public String delete() {
    return "department delete ...";
}
```

### 5 前端页面授权验证

security也可以在前端页面，加标签，来控制页面元素的展示。这里前端使用的是freemarker，需要额外做些配置，才可以使用。

#### 5.1 freemarker配置security标签

##### 5.1.1 maven依赖

```xml
<!-- ==========【freemarker权限security标签支持】========== start -->
<dependency>
    <groupId>org.springframework.security</groupId>
    <artifactId>spring-security-taglibs</artifactId>
    <version>5.3.4.RELEASE</version>
</dependency>
<dependency>
    <groupId>javax.servlet.jsp</groupId>
    <artifactId>javax.servlet.jsp-api</artifactId>
    <version>2.3.3</version>
    <scope>provided</scope>
</dependency>
<!-- ==========【freemarker权限security标签支持】========== end -->
```

##### 5.1.2 拷贝tld文件

将`spring-security-taglibs/META-INF/security.tld`，拷贝到拷贝到resource的目录tags中。

##### 5.1.3 配置

```java
/**
 * Freemarker的Security标签支持
 */
@Configuration
public class FreemarkerSecurityTaglibConfig{
    
    /**
     * security标签路径（来自"spring-security-taglibs/META-INF/security.tld"）<br>
     * 此文件需拷贝到resource的目录tags中
     */
    private static final String SECURITY_TLD_PATH="/tags/security.tld";
    
    @Autowired
    private FreeMarkerConfigurer freeMarkerConfigurer;
    
    @PostConstruct
    public void freeMarkerConfigurer() {
        List<String> classpathTlds = new ArrayList<>();
        classpathTlds.add(SECURITY_TLD_PATH);
        freeMarkerConfigurer.getTaglibFactory().setClasspathTlds(classpathTlds);
    }
}
```

#### 5.2 引入标签

freemarker前台文件ftlh，文件头，引入标签：

```html
<#assign security=JspTaglibs["http://www.springframework.org/security/tags"] />
```

#### 5.3 使用

##### 5.3.1 判断有无角色

```html
<@security.authorize access="hasRole('admin')">
	<a href="/department/test">test按钮</a>
</@security.authorize>
```

##### 5.3.2 判断有无权限

```html
<@security.authorize access="hasAuthority('department:test')">
	<a href="/department/test">test按钮</a>
</@security.authorize>
```

### 6 api验证授权

有时候，我们希望在java代码中直接判断有无某角色、有无某权限。作者对此进行了代码封装，可通过静态方法进行判断。

此判断，暂不支持权限继承。

#### 6.1 封装

```java
/**
 * security工具类
 */
public class SecurityUtils {
    
    /**
     * 默认角色前缀
     */
    private static final String DEFAULT_ROLE_PREFIX = "ROLE_";
    
    /**
     * 获取认证信息
     * @return
     */
    public static Authentication getAuthentication() {
        SecurityContext securityContext = SecurityContextHolder.getContext();
        if (securityContext != null) {
            return securityContext.getAuthentication();
        }
        return null;
    }
    
    /**
     * 判断有某权限（暂不支持权限继承）
     * @return
     */
    public static boolean hasAuthority(String authority) {
        if (StringUtils.isNotEmpty(authority)) {
            return SecurityUtils.hasAnyAuthorityName(null, authority);
        }
        return false;
    }
    
    /**
     * 判断有任一权限（暂不支持权限继承）
     * @param authorityArr
     * @return
     */
    public static boolean hasAnyAuthority(String... authorityArr) {
        if (authorityArr != null && authorityArr.length > 0) {
            return SecurityUtils.hasAnyAuthorityName(null, authorityArr);
        }
        return false;
    }
    
    /**
     * 判断有某角色（暂不支持权限继承）
     * @param role
     * @return
     */
    public static boolean hasRole(String role) {
        if (StringUtils.isNotEmpty(role)) {
            return SecurityUtils.hasAnyAuthorityName(DEFAULT_ROLE_PREFIX, role);
        }
        return false;
    }
    
    /**
     * 判断有任一角色（暂不支持权限继承）
     * @param roleArr
     * @return
     */
    public static boolean hasAnyRole(String... roleArr) {
        if (roleArr != null && roleArr.length > 0) {
            return SecurityUtils.hasAnyAuthorityName(DEFAULT_ROLE_PREFIX, roleArr);
        }
        return false;
    }
    
    /**
     * 判断是否满足通用权限信息，有一个满足即为满足（包括角色和权限）
     * @param prefix         前缀
     * @param authorityNames 权限名称
     * @return
     */
    private static boolean hasAnyAuthorityName(String prefix, String... authorityNames) {
        if (authorityNames != null && authorityNames.length > 0) {
            Set<String> authoritySet = SecurityUtils.getAuthoritySet();
            if (CollectionUtils.isNotEmpty(authoritySet)) {
                for (String authorityName : authorityNames) {
                    String defaultedRole = getRoleWithDefaultPrefix(prefix, authorityName);
                    if (authoritySet.contains(defaultedRole)) {
                        return true;
                    }
                }
            }
        }
        return false;
    }
    
    /**
     * 获取当前用户权限集合信息
     * @return
     */
    private static Set<String> getAuthoritySet() {
        Authentication authentication = SecurityUtils.getAuthentication();
        if (authentication != null) {
            Collection<? extends GrantedAuthority> userAuthorities = authentication.getAuthorities();
            return AuthorityUtils.authorityListToSet(userAuthorities);
        }
        return null;
    }
    
    /**
     * 如果defaultRolePrefix为非空且role的开头不是defaultRolePrefix，则使用defaultRolePrefix前缀角色。
     * @param defaultRolePrefix
     * @param role
     * @return
     */
    private static String getRoleWithDefaultPrefix(String defaultRolePrefix, String role) {
        if (role == null) {
            return role;
        }
        if (defaultRolePrefix == null || defaultRolePrefix.length() == 0) {
            return role;
        }
        if (role.startsWith(defaultRolePrefix)) {
            return role;
        }
        return defaultRolePrefix + role;
    }
}
```

#### 6.2 使用

java代码中直接使用静态方法判断即可，如下：

```java
// 判断有角色
SecurityUtils.hasRole("admin");
// 判断有任一角色
SecurityUtils.hasAnyRole("admin","user");
// 判断有权限
SecurityUtils.hasAuthority("user:add");
// 判断有任一权限
SecurityUtils.hasAnyAuthority("user:add","user:edit");
```

### 7 自定义授权验证失败返回方式

当系统访问认知失败时，默认返回授权验证的错误页面，这种方式对于ajax的请求，十分不友好。

因此我们希望在验证授权失败时，如果是json请求，则返回json格式的错误信息，如果是其他请求，则返回错误页面。

#### 7.1 前台页面

授权验证失败页面accessDenied.ftlh

```html
<body>
无访问权限
</body>
```

#### 7.2 后台代码

```java
/**
  * 无访问权限页面
  * @return
  */
@RequestMapping("accessDenied")
public ModelAndView accessDenied() {
    return new ModelAndView("system/accessDenied");
}
```

#### 7.3 配置

```java
// ---------- [异常处理]ExceptionTranslationFilter ----------
http.exceptionHandling()
    // 认证失败（不使用默认的表单form登录认证时，可使用此方式）
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
```

### 8 分布式session共享

可使用spring-session或tomcat-redis-session-manager。后续补充