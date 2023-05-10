package fr.leo.springsecurityuserdetailsjwt;

import java.util.ArrayList;

import org.springframework.boot.CommandLineRunner;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;

import fr.leo.springsecurityuserdetailsjwt.sec.entities.AppRole;
import fr.leo.springsecurityuserdetailsjwt.sec.entities.AppUser;
import fr.leo.springsecurityuserdetailsjwt.sec.service.AccountService;

@SpringBootApplication
@EnableGlobalMethodSecurity( prePostEnabled = true, securedEnabled = true)
public class SpringSecurityUserDetailsJwtRefactorApplication {

	public static void main(String[] args) {
		SpringApplication.run(SpringSecurityUserDetailsJwtRefactorApplication.class, args);
	}
	
	@Bean
	CommandLineRunner start(AccountService accountService  ) {
		
		return args->{
			accountService.addNewRole(new AppRole(null, "USER") );
			accountService.addNewRole(new AppRole(null, "ADMIN") );
			accountService.addNewRole(new AppRole(null, "CUSTOMER_MANAGER") );
			accountService.addNewRole(new AppRole(null, "PRODUCT_MANAGER") );
			accountService.addNewRole(new AppRole(null, "BILLS_MANAGER") );
			
			
			accountService.addNewUser(new AppUser(null, "user1", "1234", new ArrayList<>()) );
			accountService.addNewUser(new AppUser(null, "admin", "1234", new ArrayList<>()) );
			accountService.addNewUser(new AppUser(null, "user2", "1234", new ArrayList<>()) );
			accountService.addNewUser(new AppUser(null, "user3", "1234", new ArrayList<>()) );			
			accountService.addNewUser(new AppUser(null, "user4", "1234", new ArrayList<>()) );
			
			accountService.addRoleToUser("user1", "USER");
			accountService.addRoleToUser("admin", "USER");
			accountService.addRoleToUser("admin", "ADMIN");
			accountService.addRoleToUser("user2", "USER");
			accountService.addRoleToUser("user2", "CUSTOMER_MANAGER");	
			accountService.addRoleToUser("user3", "USER");
			accountService.addRoleToUser("user3", "PRODUCT_MANAGER");
			accountService.addRoleToUser("user4", "USER");
			accountService.addRoleToUser("user4", "BILLS_MANAGER");		
		};
	}
	
	/*
	 * Ici on creer une instance d'un BCryptPasswordEncoder
	 * dans le contexte de l'application
	 */
	@Bean
	public BCryptPasswordEncoder create() {
		return  new BCryptPasswordEncoder();
	}
}
