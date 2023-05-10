package fr.leo.springsecurityuserdetailsjwt.sec.repo;

import org.springframework.data.jpa.repository.JpaRepository;

import fr.leo.springsecurityuserdetailsjwt.sec.entities.AppRole;

public interface AppRoleRepository extends JpaRepository<AppRole, Long> {
	AppRole findByRoleName(String roleName);
}
