package io.security.basicsecurity.service;

import io.security.basicsecurity.domain.dto.UserDto;
import io.security.basicsecurity.domain.entity.Account;

import java.util.List;

public interface UserService {

  List<Account> getUsers();
  UserDto getUser(Long id);
  void createUser(Account account);
  void deleteUser(Long idx);
}
