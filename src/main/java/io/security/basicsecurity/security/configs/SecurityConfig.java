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

    @Bean
    public PasswordEncoder passwordEncoder() { // 평문인 비밀번호를 암호화 해준다.
        return PasswordEncoderFactories.createDelegatingPasswordEncoder();
    }

    @Override
    public void configure(WebSecurity web) throws Exception {
        /**
         * WebIgnore 설정
         * .js / css / image 파일 등의 보안 필터를 적용할 필요가 없는 리소스를 설정한다.
         * 정적 자원들은 보안 필터를 거치지 않고 통과한다.
         */
        web.ignoring().requestMatchers(PathRequest.toStaticResources().atCommonLocations());
    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {

        /**
         * WebSecurity web.ignoring() & HttpSecurity .antMatchers.permitAll()
         * 공통점 : 인증 / 권한 없어도 둘 다 통과한다.
         * 차이점:
         *  - web.ignoring(): 보안 필터를 아예 거치지 않아서, 비용적인 면에서 좋다.
         *  - permitALl() : 보안 필터를 거쳐서 검사는 받는다.
         */
        http
                .authorizeRequests()
                .antMatchers("/", "/user").permitAll()
                .antMatchers("/mypage").hasRole("USER")
                .antMatchers("/messages").hasRole("MANAGER")
                .antMatchers("/admin").hasRole("ADMIN")
                .anyRequest().authenticated()

        .and()
                .formLogin();
    }
}
