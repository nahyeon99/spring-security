package io.security.basicsecurity;

import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;

@Configuration
@EnableWebSecurity
public class SecurityConfiguration extends WebSecurityConfigurerAdapter {

    @Override
    protected void configure(HttpSecurity http) throws Exception {

        /**
         * FilterSecurityInterceptor :
         * 인가 처리, 특정 요청의 승인/거부 여부를 최종적으로 결정한다.
         * Security 가 제공하는 보안 필터 중 맨 마지막에 위치한다.
         *
         * [동작 방식]
         * 1. 사용자 request
         * 2. FilterSecurityInterceptor
         *  2-1. 인증 객체 여부 체크 (security context에 인증객체 존재 여부로 확인한다.)
         *      a. 인증 객체 null: Authentication Exception -> ExceptionTranslationFilter
         *      b. 인증 객체 Not null: 3번으로 이동
         * 3. SecurityMetadataSource : 사용자가 요청한 자원에 필요한 권한 정보를 조회해서 전달하는 클래스
         *  3-1. 권한 정보 체크
         *      a. 권한 정보 No : null 일 경우 심사하지 않는다. -> 자원 접근 허용
         *      b. 권한 정보 Yes : 4번으로 이동
         * 4. AccessDecisionManager : 최종 심의 결정자 인터페이스
         *  - 접근 결정의 세가지 유형 (AccessDecisionManager 인터페이스의 3가지 구현체)
         *      a. AffirmativeBased : 여러 개의 Voter 클래스 중 하나라도 승인 시 접근 허용
         *      b. ConsensusBased : 다수표로 결정한다.
         *                        동수일 경우 default는 접근 허용이지만, allowIfEqualGrantedDeniedDecisions: false시 접근 거부한다.
         *      c. UnanimousBased : 만장일치여야 접근 허용
         *  4-1. 심의 요청 -> AccessDecisionVoter : 심의자, 사용자의 접근 가능 여부를 심의한다.
         *      - AccessDecisionVoter
         *          - 판단을 심사하는 위원
         *          - Voter 가 권한 부여 과정에서 판단하는 자료
         *              a. Authentication : 인증 정보 (User)
         *              b. FilterInvocation : 요청 정보 (antMatcher("/user"))
         *              c. ConfigAttributes : 권한 정보 (hasRole("USER"))
         *          - 결정방식
         *              a. ACCESS_GRANTED: 접근 허용 (1)
         *              b. ACCESS_DENIED: 접근 거부 (-1)
         *              c. ACCESS_ABSTAIN : 접근 보류 (0) , Voter 가 해당 타이브이 요청에 대해 결정을 내릴 수 없는 경우
         *  4-2. AccessDecisionVoter -> AccessDecisionManager : 접근 승인(ACCESS_GRANTED) / 거부 (ACCESS_DENIED)
         *      - AccessDecisionVoter 들이 return 한 상수값(결과)을 합산해서 AccessDecisionManager 가 최종 결정을 내린다.
         *
         * 5. 접근 승인
         *  a. No(ACCESS_DENIED): AccessDeniedException -> ExceptionTranslationFilter
         *  b. Yes(ACCESS_GRANTED): 자원 접근 허용
         */

        http
                .authorizeRequests()
                .antMatchers("/user").hasRole("USER")
                .anyRequest().permitAll();
        http
                .formLogin()
                ;

    }
}
