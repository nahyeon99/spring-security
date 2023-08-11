package io.security.basicsecurity.repository;


import io.security.basicsecurity.domain.entity.PersistentLogin;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Date;
import java.util.List;

public interface RememberMeTokenRepository extends JpaRepository<PersistentLogin, String> {

    PersistentLogin findBySeries(String series);
    List<PersistentLogin> findByUsername(String username);
    Iterable<PersistentLogin> findByLastUsedAfter(Date expiration);

}
