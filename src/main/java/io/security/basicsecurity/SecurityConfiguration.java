package io.security.basicsecurity;

import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;

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
        /**
         * 인가 API 주의사항
         * 설정 시 구체적인 경로가 먼저 오고, 그것보다 큰 범위의 경로가 뒤에 오도록 설정한다. (이후 동적 인가 처리 방식 적용 예정)
         *
         * 아래 코드의 경우, 1번 코드가 먼저 실행 되어서,
         * SYS 권한의 유저가 /admin/** 모든 페이지에 접근이 가능해지는 코드가 먼저 실행된다.
         * 고로 2번 코드까지 실행되지 않아서 /admin/pay 에도 적용 되는 문제가 발생한다.
         *
         * 1. .antMatchers("/admin/**").access("hasRole('ADMIN') or hasRole('SYS')")
         * 2. .antMatchers("/admin/pay").hasRole("ADMIN")
         */
        http // 인가 API
                .authorizeRequests()
                .antMatchers("/user").hasRole("USER")
                .antMatchers("/admin/pay").hasRole("ADMIN")
                .antMatchers("/admin/**").access("hasRole('ADMIN') or hasRole('SYS')")
                .anyRequest().authenticated();
        http // 인증 API
                .formLogin();
        ;
    }
}
