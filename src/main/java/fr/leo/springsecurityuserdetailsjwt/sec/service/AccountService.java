package fr.leo.springsecurityuserdetailsjwt.sec.service;

import java.util.List;

import fr.leo.springsecurityuserdetailsjwt.sec.entities.AppRole;
import fr.leo.springsecurityuserdetailsjwt.sec.entities.AppUser;

public interface AccountService {

	AppUser addNewUser(AppUser appUser);
	AppRole addNewRole(AppRole appRole);
	void addRoleToUser( String username , String roleName);
	AppUser loadUserByUsername(String username);
	List<AppUser> listUsers();
}
