package com.learning.bankingsystem.repository;

import com.learning.bankingsystem.entity.Password;
import com.learning.bankingsystem.entity.PasswordStatus;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.UUID;

public interface PasswordRepository extends JpaRepository<Password, UUID> {
    Password findByUser_UuidAndStatus(UUID userUuid, PasswordStatus status);
}
