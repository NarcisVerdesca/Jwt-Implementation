package com.myprojects.jwtimplementation.repository;


import com.myprojects.jwtimplementation.entity.Role;
import org.springframework.data.jpa.repository.JpaRepository;

public interface RoleRepository extends JpaRepository<Role,Long> {

    Role findByName(String name);
}
