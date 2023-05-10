package fr.leo.springsecurityuserdetailsjwt.sec.service;

import java.util.List;

import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import fr.leo.springsecurityuserdetailsjwt.sec.entities.AppRole;
import fr.leo.springsecurityuserdetailsjwt.sec.entities.AppUser;
import fr.leo.springsecurityuserdetailsjwt.sec.repo.AppRoleRepository;
import fr.leo.springsecurityuserdetailsjwt.sec.repo.AppUserRepository;
import lombok.AllArgsConstructor;

@Service
@Transactional @AllArgsConstructor
public class AccountServiceImpl implements AccountService { 
	
	private BCryptPasswordEncoder bCryptPasswordEncoder;
	private AppUserRepository appUserRepository;
	private AppRoleRepository appRoleRepository;

	@Override
	public AppUser addNewUser(AppUser appUser) {
		String password = appUser.getPassword();
		appUser.setPassword(bCryptPasswordEncoder.encode(password));
		return appUserRepository.save(appUser);
	}

	@Override
	public AppRole addNewRole(AppRole appRole) {
		return appRoleRepository.save(appRole);
	}

	@Override
	public void addRoleToUser(String username, String roleName) {
		AppUser appuser = appUserRepository.findByUsername(username);
		AppRole approle = appRoleRepository.findByRoleName(roleName);	
		appuser.getAppRoles().add(approle);
	}

	@Override
	public AppUser loadUserByUsername(String username) {
		return appUserRepository.findByUsername(username);
	}

	@Override
	public List<AppUser> listUsers() {
		return appUserRepository.findAll();
	}
}
