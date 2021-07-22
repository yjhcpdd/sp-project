package com.demo.sp.security.form.config.system;

import freemarker.ext.jsp.TaglibFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.servlet.view.freemarker.FreeMarkerConfigurer;

import javax.annotation.PostConstruct;
import java.util.ArrayList;
import java.util.List;

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
