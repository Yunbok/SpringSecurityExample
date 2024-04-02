package org.yunbok.example.repository;

import org.springframework.data.repository.CrudRepository;
import org.springframework.stereotype.Repository;
import org.yunbok.example.entity.User;

import java.util.Optional;

@Repository
public interface UserRepository extends CrudRepository<User, Integer> {

    boolean existsByUsername(String username);
    Optional<User> findByUsername(String username);
}
