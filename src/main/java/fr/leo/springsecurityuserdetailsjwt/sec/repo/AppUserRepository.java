package fr.leo.springsecurityuserdetailsjwt.sec.repo;

import org.springframework.data.jpa.repository.JpaRepository;

import fr.leo.springsecurityuserdetailsjwt.sec.entities.AppUser;

public interface AppUserRepository extends JpaRepository<AppUser, Long> {
	AppUser findByUsername(String username);
}
