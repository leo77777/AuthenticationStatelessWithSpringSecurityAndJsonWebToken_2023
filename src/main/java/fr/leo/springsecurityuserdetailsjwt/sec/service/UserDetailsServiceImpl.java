package fr.leo.springsecurityuserdetailsjwt.sec.service;

import java.util.ArrayList;
import java.util.Collection;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import fr.leo.springsecurityuserdetailsjwt.sec.entities.AppUser;
import lombok.AllArgsConstructor;

@Service
@AllArgsConstructor
public class UserDetailsServiceImpl implements UserDetailsService {	
	
 	/* 
	  Cette interface contient 1 seule méthode, qui prend en parametre "username" !
	
	  Elle retourne un objet "user", ... mais un objet "user" de Spring !
	  Pour Spring, un "user" est un objet qui implémente l'interface "UserDetails".
	
	  Et donc ici on dit à SpringSecurity,
	   "lorsque un utilisateur va saisir son username et son mot de passe, 
	   appelle la méthode 'loadUserByUsername( username )' en prenant en paramètre le 			//  username saisi par l'utilisateur, et c'est à moi maintenant de te dire dans 
	   cette méthode tu va chercher cet utilisateur",
	   ou est ce que tu va aller chercher cet utilisateur" !
	*/
	
	private AccountService accountService; 
	@Override
	public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
		AppUser appUser =  accountService.loadUserByUsername(username);
		
		/* Ci dessous,on voit "USer", c'est la classe "User" de Spring :
		    import org.springframework.security.core.userdetails.User;
		   C'est une classe qui "implemente UserDetails" !
		   Le constructeur de cette classe attend en paramètre:
		   String username, String password, La liste des roles dans un objet
		    qui est une collection d'objets de type "GrantedAuthority" !
		*/
		if (appUser != null) {
			Collection<GrantedAuthority> authorities = new ArrayList<>();
			appUser.getAppRoles().forEach(
			     role -> { authorities.add( new SimpleGrantedAuthority(role.getRoleName()));}
			);
			return new User(appUser.getUsername(), appUser.getPassword(), authorities );	
			
		/*
				Collection<GrantedAuthority> collect = appUser.getAppRoles()
				.stream()
				.map(role ->{ return new SimpleGrantedAuthority(role.getRoleName());  } ) 
				.collect(Collectors.toList());
				return new User(appUser.getUsername(), appUser.getPassword(), collect );
			*/
			
		}else {
			/*
			 * On est obligé de traiter ce cas, sinon on a une erreur 
			 */
			return new User("a", "a", new ArrayList<GrantedAuthority>() );
		}	
	}
}
