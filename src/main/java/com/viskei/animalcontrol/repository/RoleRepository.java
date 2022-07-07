package com.viskei.animalcontrol.repository;

import com.viskei.animalcontrol.model.ERole;
import com.viskei.animalcontrol.model.Role;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.Optional;

@Repository
public interface RoleRepository extends JpaRepository<Role, Long> {
  Optional<Role> findByName(ERole name);
}
