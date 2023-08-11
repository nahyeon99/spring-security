package io.security.basicsecurity.config;

import io.security.basicsecurity.security.configs.MethodSecurityConfig;
import org.springframework.boot.autoconfigure.AutoConfigureBefore;
import org.springframework.context.annotation.Configuration;

@Configuration
@AutoConfigureBefore({MethodSecurityConfig.class})
public class AppConfig {

   /* @Bean
    public SecurityResourceService securityResourceService(ResourcesRepository resourcesRepository*//*, RoleHierarchyImpl roleHierarchy*//*,RoleHierarchyServiceImpl roleHierarchyService, AccessIpRepository accessIpRepository*//*, MapBasedMethodSecurityMetadataSource mapBasedMethodSecurityMetadataSource, AnnotationConfigServletWebServerApplicationContext applicationContext, CustomMethodSecurityInterceptor methodSecurityInterceptor*//*) {
        SecurityResourceService SecurityResourceService = new SecurityResourceService(resourcesRepository, *//*roleHierarchy, *//*roleHierarchyService, accessIpRepository*//*, mapBasedMethodSecurityMetadataSource, applicationContext, methodSecurityInterceptor*//*);
        return SecurityResourceService;
    }*/

//    @Bean
//    public DefaultAdvisorAutoProxyCreator defaultAdvisorAutoProxyCreator() {
//        DefaultAdvisorAutoProxyCreator defaultAdvisorAutoProxyCreator = new DefaultAdvisorAutoProxyCreator();
//        return defaultAdvisorAutoProxyCreator;
//    }
}
