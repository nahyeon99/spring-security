package io.security.basicsecurity.security.configs;

import io.security.basicsecurity.security.common.FormWebAuthenticationDetailsSource;
import io.security.basicsecurity.security.handler.CommonAccessDeniedHandler;
import io.security.basicsecurity.security.handler.FormAuthenticationFailureHandler;
import io.security.basicsecurity.security.handler.FormAuthenticationSuccessHandler;
import io.security.basicsecurity.security.provider.FormAuthenticationProvider;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.security.servlet.PathRequest;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.crypto.factory.PasswordEncoderFactories;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.access.AccessDeniedHandler;
import org.springframework.security.web.authentication.LoginUrlAuthenticationEntryPoint;

@Configuration
@EnableWebSecurity
@Order(1)
public class SecurityConfig extends WebSecurityConfigurerAdapter {

    @Autowired
    private FormWebAuthenticationDetailsSource authenticationDetailsSource;

    @Autowired
    private FormAuthenticationSuccessHandler formAuthenticationSuccessHandler;
    @Autowired
    private FormAuthenticationFailureHandler formAuthenticationFailureHandler;

    @Override
    public void configure(WebSecurity web) throws Exception {
        web.ignoring().requestMatchers(PathRequest.toStaticResources().atCommonLocations());
    }
    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        auth.authenticationProvider(authenticationProvider());
    }

    @Override
    public AuthenticationManager authenticationManagerBean() throws Exception {
        return super.authenticationManagerBean();
    }


    private AuthenticationProvider authenticationProvider() {
        return new FormAuthenticationProvider();
    }

    @Override
    protected void configure(final HttpSecurity http) throws Exception {

        http
                .authorizeRequests()
                .antMatchers("/mypage").hasRole("USER")
                .antMatchers("/messages").hasRole("MANAGER")
                .antMatchers("/admin").hasRole("ADMIN")
                .antMatchers("/**").permitAll()
                .anyRequest().authenticated()

                .and()
                .formLogin()
                .loginPage("/login")
                .loginProcessingUrl("/login_proc")
                .successHandler(formAuthenticationSuccessHandler)
                .failureHandler(formAuthenticationFailureHandler)
                .authenticationDetailsSource(authenticationDetailsSource)
                .permitAll()

                .and()
                .exceptionHandling()
                .authenticationEntryPoint(new LoginUrlAuthenticationEntryPoint("/login"))
                .accessDeniedPage("/denied")
                .accessDeniedHandler(accessDeniedHandler())
        ;

    }

    @Bean
    public AccessDeniedHandler accessDeniedHandler() {
        CommonAccessDeniedHandler accessDeniedHandler = new CommonAccessDeniedHandler();
        accessDeniedHandler.setErrorPage("/denied");

        return accessDeniedHandler;
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return PasswordEncoderFactories.createDelegatingPasswordEncoder();
    }

}
