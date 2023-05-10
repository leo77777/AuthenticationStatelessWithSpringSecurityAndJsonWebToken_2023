package fr.leo.springsecurityuserdetailsjwt.web;

import java.security.Principal;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.transaction.Transactional;

import org.springframework.security.access.prepost.PostAuthorize;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.interfaces.DecodedJWT;
import com.auth0.jwt.interfaces.JWTVerifier;
import com.fasterxml.jackson.databind.ObjectMapper;

import fr.leo.springsecurityuserdetailsjwt.sec.entities.AppRole;
import fr.leo.springsecurityuserdetailsjwt.sec.entities.AppUser;
import fr.leo.springsecurityuserdetailsjwt.sec.service.AccountService;
import fr.leo.springsecurityuserdetailsjwt.util.JWTUtil;
import lombok.AllArgsConstructor;
import lombok.Data;

@RestController
@AllArgsConstructor
@Transactional
public class AccountRestController {
	
	AccountService accountServiceImpl;

	@GetMapping(path ="/users")
	@PostAuthorize("hasAuthority('USER')")
	public List<AppUser> users(){
		return accountServiceImpl.listUsers();
	}
	
	@PostMapping(path = "/users")
	@PostAuthorize("hasAuthority('ADMIN')")
	public AppUser saveUser( @RequestBody AppUser appUser ) {
		return accountServiceImpl.addNewUser(appUser);
	}
	
	@PostMapping(path = "/roles")
	@PostAuthorize("hasAuthority('ADMIN')")
	public AppRole saveRole( @RequestBody AppRole appRole ) {
		return accountServiceImpl.addNewRole(appRole);
	}
	
	@PostMapping(path = "/addRoleToUser")
	public void addRoleToUser( @RequestBody RoleUserForm roleUserForm ) {
		accountServiceImpl.addRoleToUser(roleUserForm.getUsername(), roleUserForm.getRoleName());
	}
	
	/*
	 * Avec Spring, on peut toujours injecter les objets "request" et "response"
	 *  là ou on en a besoin !
	 */
	@GetMapping(path = "/refreshToken") 
	public void refreshToken( HttpServletRequest request, HttpServletResponse response ) 
		throws Exception{
		String authToken = request.getHeader(JWTUtil.AUTH_HEADER);
		System.out.println(authToken);
		if ( (authToken != null) && ( authToken.startsWith(JWTUtil.PREFIX) ) ) {
			try {
				String jwt = authToken.substring(JWTUtil.PREFIX.length()); // on enleve le "Bearer " 
				Algorithm algorithm = Algorithm.HMAC256(JWTUtil.SECRET);
				JWTVerifier jwtVerifier = JWT.require(algorithm).build();
				DecodedJWT decodedJWT =  jwtVerifier.verify(jwt); // retourne le token vérifié, ou une exception !
				
				// On récupère le username de la personne authentifiée
				String username = decodedJWT.getSubject();
				System.out.println("Username : " + username );
				
				/*
				 * ON A PAS BESOIN DES ROLES CETTE FOIS CI !
				 */
//				String[] roles = decodedJWT.getClaim("roles").asArray(String.class);
//				Collection<GrantedAuthority> authorities = new ArrayList<>();
//				for (String  role : roles) {
//					authorities.add(new SimpleGrantedAuthority(role));
//				}
				
				/*
				 * Maintenant, que on a le username, on peut aller vérifier
				 *  si l'utilisateur est toujours autorisé !
				 *  En effet pour une raison ou une autre, il a put entre temps
				 *   être retiré de la liste des utilisateurs autorisés
				 */
				AppUser appUser = accountServiceImpl.loadUserByUsername(username);
				
				/*
				 * Maintenant on suppose que l'utilisateur est toujours autorisé,
				 * 	et donc on va lui génerer un nouvel "access-token" !
				 */				
				String jwtAccesToken = JWT.create()
						.withSubject(appUser.getUsername())
						.withExpiresAt(new Date(System.currentTimeMillis() + JWTUtil.EXPIRE_ACCESS_TOKEN))// millisecondes : 30 minutes
						.withIssuer(request.getRequestURI().toString()) 
						.withClaim("roles", appUser.getAppRoles() // ici les claims privés 
								.stream()
								.map(r->r.getRoleName())
								.collect(Collectors.toList()))
						.sign(algorithm); // ici on créer la signature ! 
				
				Map<String, String> idToken = new HashMap<>();
				idToken.put("access-token", jwtAccesToken);
				/*
				 * ICI LE REFRESH-TOKEN ON GARDE LE MEME QUE CELUI ENVOYER !
				 */
				idToken.put("refresh-token", jwt);	
				response.setContentType("application/json");
				new ObjectMapper().writeValue(response.getOutputStream(), idToken);					
			} catch (Exception e) {
				throw e;
			}
		}else {
			throw new RuntimeException("Refresh Token Requred !");
		}
	}
	
	/*
	 * Avec SpringSecurity pour connaitre l'utilisateur
	 *  authentifié, il y a l'objet "Principal"
	 *  "Principal" c'est le username de l'utilisateur
	 */
	@GetMapping(path = "/profile")
	public AppUser profile(Principal principal) {
		String username = principal.getName();
		return accountServiceImpl.loadUserByUsername(username);
	}
}

@Data
class RoleUserForm{
	private String username;
	private String roleName; 
}
