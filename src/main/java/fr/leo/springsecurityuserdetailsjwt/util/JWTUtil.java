package fr.leo.springsecurityuserdetailsjwt.util;

public class JWTUtil {
	
	public static final  String SECRET = "mySecret1234";
	public static final  String AUTH_HEADER = "Authorization";
	public static final  long EXPIRE_ACCESS_TOKEN = 1*30*1000;
	public static final  long EXPIRE_REFRESH_TOKEN = 14*60*1000;
	
	public static final  String PREFIX = "Bearer ";

}
