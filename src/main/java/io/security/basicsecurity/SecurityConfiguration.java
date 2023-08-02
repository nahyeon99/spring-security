package io.security.basicsecurity;

import org.springframework.context.annotation.Configuration;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.security.web.access.AccessDeniedHandler;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.savedrequest.HttpSessionRequestCache;
import org.springframework.security.web.savedrequest.RequestCache;
import org.springframework.security.web.savedrequest.SavedRequest;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

@Configuration
@EnableWebSecurity
public class SecurityConfiguration extends WebSecurityConfigurerAdapter {

    // AuthenticationManagerBuilder class: 사용자를 생성하고, 권한을 설정할 수 있는 기능 제공
    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        // passwordencoder : prefix 기재 필수
        auth.inMemoryAuthentication().withUser("user").password("{noop}1111").roles("USER");
        auth.inMemoryAuthentication().withUser("sys").password("{noop}1111").roles("SYS");
        auth.inMemoryAuthentication().withUser("admin").password("{noop}1111").roles("ADMIN");
    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {

        http // 인가 API
                .authorizeRequests()
                .antMatchers("/login").permitAll() // 인가는 .authenticated() 필요, 인증만 필요 없음
                .antMatchers("/user").hasRole("USER")
                .antMatchers("/admin/pay").hasRole("ADMIN")
                .antMatchers("/admin/**").access("hasRole('ADMIN') or hasRole('SYS')")
                .anyRequest().authenticated();
        http // 인증 API
                .formLogin()
                .successHandler(new AuthenticationSuccessHandler() {
                    @Override
                    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication) throws IOException, ServletException {
                        /**
                         * 인증 예외시 이전 미인증 사용자 요청을 세션에 저장해서 꺼내 쓴다.
                         * 1. savedRequest 객체에 이전 요청을 저장한다.
                         * 2. 객체를 session 에 저장한다.
                         * 3. HttpSessionRequestCache 클래스의 객체가 1,2번 동작을 작동시킨다.
                         */
                        RequestCache requestCache = new HttpSessionRequestCache();
                        SavedRequest savedRequest = requestCache.getRequest(request, response);
                        String redirectUrl = savedRequest.getRedirectUrl();
                        response.sendRedirect(redirectUrl);
                    }
                });
        http
                /**
                 * FilterSecurityInterceptor :
                 * - 주로 AuthenticationException(인증 예외) / AccessDeniedException(인가 예외) 를 throw 하는 필터이다.
                 * - 시큐리티가 관리하는 보안 필터 중에 맨 마지막에 위치한다.
                 * - 이 필터 바로 앞에 위치하는 필터가 ExceptionTranslationFilter 이다.
                 *
                 * ExceptionTranslationFilter
                 * 즉, FilterSecurityInterceptor 가 던지는 인증/인가 예외를 catch 해서 처리하는 필터이다.
                 */
                .exceptionHandling() // 예외 처리 기능이 작동, ExceptionHandlerFilter 동작
                // 인증 예외 : 401 오류 코드 전달
                .authenticationEntryPoint(new AuthenticationEntryPoint() { // 인증 예외, AuthenticationEntryPoint 인터페이스를 직접 구현
                    @Override
                    public void commence(HttpServletRequest request, HttpServletResponse response, AuthenticationException authException) throws IOException, ServletException {
                        // 직접 구현했으므로, spring security 가 제공하는 기본 로그인 페이지가 아닌 우리가 직접 만든 로그인 페이지로 이동한다.
                        response.sendRedirect("/login");
                    }
                })
                // 인가 예외 : 403 오류 코드 전달
                .accessDeniedHandler(new AccessDeniedHandler() {
                    @Override
                    public void handle(HttpServletRequest request, HttpServletResponse response, AccessDeniedException accessDeniedException) throws IOException, ServletException {
                        response.sendRedirect("/denied");
                    }
                })
        ;
    }
}
