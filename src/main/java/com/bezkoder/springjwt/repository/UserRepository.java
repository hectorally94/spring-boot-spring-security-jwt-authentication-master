package com.bezkoder.springjwt.repository;

import java.util.Optional;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import com.bezkoder.springjwt.models.User;

@Repository
public interface UserRepository extends JpaRepository<User, Long> {
  Optional<User> findByUsername(String username);
  Optional<User> findByUsernameAndPhoneNumber(String username,String phoneNumber);

  Boolean existsByUsername(String username);

  Boolean existsByPhoneNumber(String phoneNumber);

  Boolean existsByUsernameAndPhoneNumber(String username,String phoneNumber);
}