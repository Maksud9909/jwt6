package com.maksudrustamov.springboot.jwt6.repository;

import com.maksudrustamov.springboot.jwt6.user.User;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;

public interface UserRepository extends JpaRepository<User,Integer> {
    Optional<User> findbyEmail(String email); // Находить пользователя через имейл
}
