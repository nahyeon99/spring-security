package io.security.basicsecurity.security.configs;

import org.springframework.boot.autoconfigure.security.servlet.PathRequest;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.crypto.factory.PasswordEncoderFactories;
import org.springframework.security.crypto.password.PasswordEncoder;

@Configuration
@EnableWebSecurity
public class SecurityConfig extends WebSecurityConfigurerAdapter {

    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {

        String password = passwordEncoder().encode("1111");

        auth.inMemoryAuthentication().withUser("user").password(password).roles("USER");
        auth.inMemoryAuthentication().withUser("manager").password(password).roles("MANAGER", "USER");
        auth.inMemoryAuthentication().withUser("admin").password(password).roles("ADMIN", "USER", "MANAGER");
    }

    /**
     * PasswordEncoder
     * - 비밀번호를 안전하게 암호화 기능 제공
     * - Spring Security 5.0 이전에는 NoOpPasswordEncoder (평문 암호화 -> 평문, 현재는 deprecated)
     *
     * - 암호화 포맷: {id}encodedPassword
     *  - 기본 포맷은 Bcrypt: {bcrypt}$2a$10$dXJ3SW..
     *  - 알고리즘 종류 : bcrypt, noop, pbkdf2, scrypt, sha256 ...
     *
     * - 인터페이스
     *  - encode(password) : 패스워드 암호화
     *  - matches(rawPassword, encodedPassword) : 패스워드 비교
     */

    @Bean
    public PasswordEncoder passwordEncoder() {
        // PasswordEncoder 생성
        // 여러 개의 PasswordEncoder 유형을 선언한 뒤, 상황에 맞게 선택해서 사용할 수 있도록 지원하는 Encoder
        return PasswordEncoderFactories.createDelegatingPasswordEncoder();
    }

    @Override
    public void configure(WebSecurity web) throws Exception {
        web.ignoring().requestMatchers(PathRequest.toStaticResources().atCommonLocations());
    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {

        http
                .authorizeRequests()
                .antMatchers("/", "/users").permitAll()
                .antMatchers("/mypage").hasRole("USER")
                .antMatchers("/messages").hasRole("MANAGER")
                .antMatchers("/admin").hasRole("ADMIN")
                .anyRequest().authenticated()

        .and()
                .formLogin();
    }
}
