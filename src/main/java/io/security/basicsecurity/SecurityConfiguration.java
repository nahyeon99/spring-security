package io.security.basicsecurity;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
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
                 * 세션 고정 보호 API
                 * 1. servlet 3.1 이상 default, 공격자의 세션 ID는 무용지물이 되고, 새 유저가 인증 시 새로운 세션 ID를 제공한다.
                 * .sessionFixation().changeSessionId()
                 * 2. 동시 로그인 접속자에게 동일한 세션 ID를 제공한다.
                 * .sessionFixation().none()
                 * 3. servlet 3.1 이하 default, 새로운 세션을 생성 후 migrate
                 * .sessionFixation().migrateSession()
                 * 4. 새로운 세션을 생성한다.
                 * .sessionFixation().newSession()
                 */
                .sessionManagement() // 세션 관리 기능이 작동한다.
                .sessionFixation().changeSessionId();
    }
}
