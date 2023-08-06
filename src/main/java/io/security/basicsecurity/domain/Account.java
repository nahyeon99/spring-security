package io.security.basicsecurity.domain;

import lombok.Data;

import javax.persistence.Entity;
import javax.persistence.GeneratedValue;
import javax.persistence.Id;

@Entity // JPA가 관리하는 클래스, DB의 테이블과 매핑이 되는 클래스
@Data // lombok 지원, 컴파일 되는 시점에 getter/setter 등 기능을 제공
public class Account {

    @Id
    @GeneratedValue
    private Long id;
    private String username;
    private String password;
    private String email;
    private String age;
    private String role;
}
