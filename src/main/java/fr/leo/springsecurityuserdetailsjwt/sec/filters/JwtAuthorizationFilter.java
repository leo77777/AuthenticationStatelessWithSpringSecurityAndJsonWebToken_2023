package fr.leo.springsecurityuserdetailsjwt.sec.filters;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Collection;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.OncePerRequestFilter;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.interfaces.DecodedJWT;
import com.auth0.jwt.interfaces.JWTVerifier;

import fr.leo.springsecurityuserdetailsjwt.util.JWTUtil;

public class JwtAuthorizationFilter extends OncePerRequestFilter {

	/* La classe "OncePerRequestFilter" contient 1 méthode abstraite à redéfinir :  
	     doFilterInternal() 
	   Cette méthode se lance chaque fois que il y a une requete.
	   On intercepte la requete avant qu'elle n'atteigne DispatcherServlet !
	 */
	@Override
	protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
			throws ServletException, IOException {
		/*
		 * Si c'est une requete de "refreshToken", 
		 * et bien on shunte le filtre "JwtAuthorizationFilter" 
		 * puisque on va vers une méthode qui va nous donner ou pas un 
		 * nouvel 'access-token".
		 * Si j'obtien le "access-token" je serais alors authentifié,
		 *  et sinon : et bien je n'aurais de toute facon pas access à l'application
		 *  car je ne suis pas authentifié !
		 */
		if (request.getServletPath().equals("/refreshToken")) {
			filterChain.doFilter(request, response);
		}else {
			
			String authorizationToken = request.getHeader(JWTUtil.AUTH_HEADER);
			
			/* On vérifie que le header commence avec "Bearer ". En effet le header "Authorization" peut
		     	etre utilisé pour l'authentification Http, en dans ce cas là il commence avec
			 	"Basic " !   Par contre "Bearer " c'est pour dire que on utilise un token !
			 	"Bearer" ça veut dire "porteur" !
			 */
			if (authorizationToken != null && authorizationToken.startsWith(JWTUtil.PREFIX)) {
				try {
					String jwt = authorizationToken.substring(JWTUtil.PREFIX.length()); // on enleve le "Bearer " 
					/* Ici on utilise la meme clé pour crypter et pour décrypter.
				       Alors que avec rsa, on utilise une clé privée pour crypter et une
				    	clé public pour décrypter 	
					*/  
					Algorithm algorithm = Algorithm.HMAC256(JWTUtil.SECRET);
					JWTVerifier jwtVerifier = JWT.require(algorithm).build();
					DecodedJWT decodedJWT =  jwtVerifier.verify(jwt); // retourne le token vérifié, ou une exception !
					
					// On récupère le username de la personne authentifiée
					String username = decodedJWT.getSubject();
					
					/*
					 * On transforme la liste de roles au format String
					 *  en une liste de "GrantedAuthority"
					 */
					String[] roles = decodedJWT.getClaim("roles").asArray(String.class);
					Collection<GrantedAuthority> authorities = new ArrayList<>();
					for (String  role : roles) {
						authorities.add(new SimpleGrantedAuthority(role));
					}
					
					/*
					 * Maintenant, SpringSecurity doit authentifier la personne !
					 * Ici le 2ème paramètre, cad le motDePasse, on en a pas besoin !
					 */
					UsernamePasswordAuthenticationToken authenticationToken =
							new UsernamePasswordAuthenticationToken(username, null, authorities);
					
					/* Ici SpringSecurity va authentifier cette personne !
					   afin de savoir si la personne a le droit ou pas d'acceder à cette ressource !
					*/			
					SecurityContextHolder.getContext().setAuthentication(authenticationToken);
					
					/* Maintenant qui'il est authentifié, on peut lui dire "tu peux passer" !
					 * Pour cela on utilise le parametre "filterChain" qui a été passé en 
					 * paramètre à la méthode, et on lui dit "tu passes au filtre suivant !"
					 * Dans les autres framework c'est ".next()" !
					 *      Donc au final :
					 *      		on intercepte la requete
					 *      		je fais les vérifications
					 *      		je lui dis "tu passes au filtre suivant !" 
					 *         ... et donc SpringSecurity il va orienter la requete vers DispatcherServlet , 
					 *         	    ou un autre filtre, ect 
					 * Ici on passe au filtre suivant, mais ON A spécifié dans l'instruction
					 *    juste avant "je te connais" !
					*/ 
					filterChain.doFilter(request, response);
				} catch (Exception e) {
					response.setHeader("error-message", e.getMessage());
					response.sendError(HttpServletResponse.SC_FORBIDDEN);
				}			
			}else {
				/*
				 * Si on a une requete qui ne contient le header "Authorization",
				     et bien on passe au filtre suivant.
				   Si la ressource nécessite une authentification, et bien SpringSecurity
				     il va l'interdire,
				     si ça nécessite pas une authentification, il va le laisser passer !
				   Ici on passe au filtre suivant, mais ON A PAS spécifié dans l'instruction
				     juste avant "je te connais" !	
				 */
				filterChain.doFilter(request, response);
			}	
			
		}
		
		
	}
}
