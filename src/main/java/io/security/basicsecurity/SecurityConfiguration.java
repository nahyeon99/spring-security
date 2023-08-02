package io.security.basicsecurity;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.authentication.logout.LogoutHandler;
import org.springframework.security.web.authentication.logout.LogoutSuccessHandler;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;
import java.io.IOException;

@Configuration
@EnableWebSecurity
public class SecurityConfiguration extends WebSecurityConfigurerAdapter {

    @Autowired
    UserDetailsService userDetailsService;

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http // 인가 API
                .authorizeRequests()
                .anyRequest().authenticated();
        http // 인증 API
                .formLogin();
        http
                /**
                 * 세션 정책 API
                 * http.sessionManagement()
                 *      .sessionCreationPolicy(Session.CreationPolicy.If_Required)
                 * Always : 스프링 시큐리티가 항상 세션 생성
                 * If_Required : 스프링 시큐리티가 필요 시 생성 (default)
                 * Never : 스프링 시큐리티가 생성하지 않지만, 이미 존재하면 사용
                 * Stateless : 생성하지 않고, 존재해도 사용하지 않음,
                 *             JWT 인증 방식 같이 아예 세션을 사용하지 않는 방식은 이 방식을 사용한다.
                 */
                .sessionManagement() // 세션 관리 기능이 작동한다.
                .sessionCreationPolicy(SessionCreationPolicy.IF_REQUIRED);
    }
}
