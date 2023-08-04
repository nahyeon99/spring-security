package io.security.basicsecurity;

import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.context.SecurityContextHolder;

@Configuration
@EnableWebSecurity
public class SecurityConfiguration extends WebSecurityConfigurerAdapter {

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http
                .authorizeRequests()
                .anyRequest().authenticated();
        http
                .formLogin()
                ;

        /**
         * Authentication
         *
         * 1. request Login (username + password)
         * 2. UsernamePasswordAuthenticationFilter
         *      2-1. Authentication 객체 생성
         *          principal : admin@security.com
         *          credentials : password
         *          authorities : ...
         *          authenticated : false
         *      2-2. AuthenticationManager (인증 처리 - 인증 성공 / 실패)
         *      2-3. 안증 성공 시  Authentication 객체에 최종 인증 결과를 저장한다.
         *          principal : admin@security.com
         *          credentials : --- (보안적으로 비워두기도 함)
         *          authorities : ROLE_ADMIN
         *          authenticated : true
         * 3. ThreadLocal > SecurityContextHolder > SecurityContext > Authentication 객체를 저장한다.
         *      인증 객체를 전역 사용 가능하다.
         *
         *  SecurityContext
         *  - Authentication 객체가 저장되는 보관소
         *  - 필요시 언제든지 Authentication 객체를 꺼내어 쓸 수 있도록 제공되어지는 클래스
         *  - ThreadLocal 에 저장되어 아무 곳 에서나 참조가 가능하다.
         *  - 인증이 완료되면 HttpSession 에 저장되어 어플리케이션 전반에 걸쳐 전역적인 참조가 가능하다.
         *      -> HttpSession 에 SPRING_SECURITY_CONTEXT 이름으로 SecurityContextHolder 에 최종적으로 저장된다.
         *
         * SecurityContextHolder
         * - SecurityAContext 를 담고 있다.
         * - SecurityContext 객체 저장 방식
         *      1. MODE_THREADLOCAL : default, 스레드 당 SecurityContext 객체를 할당한다.
         *      2. MODE_INHERITABLETHREADLOCAL : 메인 스레드와 자식 스레드에 관하여 동일한 SecurityContext 를 유지한다.
         *      3. MODE_GLOBAL : 응용 프로그램에서 단 하나의 SecurityContext 를 저장한다.
         *
         */
        SecurityContextHolder.setStrategyName(SecurityContextHolder.MODE_INHERITABLETHREADLOCAL);
    }
}
